





Below is a complete configuration-driven design for your aggregator. It keeps your existing SQLite reader and `SQLServer.cs` implementation; it does not replace either one.

The responsibilities are:

- `app.config` defines source tables, destination tables, table types, parent relationships, keys, column mappings, and SQL Server join conditions.
- `AggregatorConfig.cs` reads and validates the configuration.
- `DataAggregator.cs` processes tables in parent-before-child order.
- Your existing `SQLServer.cs` creates destination tables using the configured keys and `JoinConditions`, and handles data insertion/update.
- Your existing SQLite class reads each source table into a `DataTable`.

Importantly, the aggregator does not execute `JoinConditions` against SQLite data. They are passed to SQL Server table creation only.

## 1. Complete app.config

For a valid .NET Framework configuration file, declare the custom `aggregator` section under `configSections`. The `IgnoreSection` declaration allows us to keep the configuration as ordinary XML and read it using `XDocument`.

The following is an illustrative configuration. Replace the sample column names and keys with those in your actual database.

```
<?xml version="1.0" encoding="utf-8"?>
<configuration>

  <configSections>
    <section
      name="aggregator"
      type="System.Configuration.IgnoreSection, System.Configuration"
      allowLocation="true"
      allowDefinition="Everywhere" />
  </configSections>

  <aggregator>

    <Tables>

      <!-- Property table -->
      <Table
        name="TestRunProperty"
        type="Property"
        sourceTable="TestRunProperty"
        destinationTable="SDA_TestRunProperty"
        primaryKey="PropertyID"
        uniqueKey="PropertyID,TestRunID">

        <Columns>
          <Column source="PropertyID" />
          <Column source="TestRunID" />
          <Column source="PropertyName" />
          <Column source="PropertyValue" />
        </Columns>

      </Table>


      <!-- Root table: a Root is allowed to have a Property parent -->
      <Table
        name="MOSS"
        type="Root"
        sourceTable="MOSS_table"
        destinationTable="SDA_MOSS"
        parent="TestRunProperty"
        primaryKey="MOSS_ID"
        uniqueKey="MOSS_ID,TestRunID">

        <JoinConditions operator="AND">
          <Condition
            parentColumn="PropertyID"
            childColumn="PropertyID" />

          <Condition
            parentColumn="TestRunID"
            childColumn="TestRunID" />
        </JoinConditions>

        <Columns>
          <Column source="MOSS_ID" />
          <Column source="PropertyID" />
          <Column source="TestRunID" />
          <Column source="MOSS_Name" destination="MOSS_Name" />
        </Columns>

      </Table>


      <!-- Child table -->
      <Table
        name="MOSS_Child"
        type="Child"
        sourceTable="MOSS_Child_table"
        destinationTable="SDA_MOSS_Child"
        parent="MOSS"
        primaryKey="Child_ID"
        uniqueKey="Child_ID,TestRunID">

        <JoinConditions operator="AND">
          <Condition
            parentColumn="MOSS_ID"
            childColumn="MOSS_ID" />

          <Condition
            parentColumn="TestRunID"
            childColumn="TestRunID" />
        </JoinConditions>

        <Columns>
          <Column source="Child_ID" />
          <Column source="MOSS_ID" />
          <Column source="TestRunID" />
          <Column source="Child_Name" />
        </Columns>

      </Table>


      <!-- A Child table can also be the parent of another Child table -->
      <Table
        name="MOSS_Child_2"
        type="Child"
        sourceTable="MOSS_Child_table_2"
        destinationTable="SDA_MOSS_Child_2"
        parent="MOSS_Child"
        primaryKey="Child2_ID"
        uniqueKey="Child2_ID,TestRunID">

        <JoinConditions operator="AND">
          <Condition
            parentColumn="Child_ID"
            childColumn="Child_ID" />

          <Condition
            parentColumn="TestRunID"
            childColumn="TestRunID" />
        </JoinConditions>

        <Columns>
          <Column source="Child2_ID" />
          <Column source="Child_ID" />
          <Column source="TestRunID" />
          <Column source="Description" />
        </Columns>

      </Table>

    </Tables>

  </aggregator>

</configuration>
```

A few configuration rules:

- `name` is the logical name used by the aggregator and by `parent`.
- `sourceTable` is the SQLite table name.
- `destinationTable` is the SQL Server table name.
- `parent` is optional for `Property` and `Root`; it is required for `Child` in this example.
- `JoinConditions` is optional. When present, it is passed to the SQL Server table-creation logic.
- `primaryKey` and `uniqueKey` are metadata passed to your existing SQL Server implementation.
- If a destination column has the same name as its source column, you can omit `destination`.

## 2. C# configuration classes

Create `AggregatorConfig.cs`.

```
using System;
using System.Collections.Generic;
using System.Data;
using System.IO;
using System.Linq;
using System.Xml.Linq;

namespace DataAggregator
{
    public enum TableType
    {
        Property,
        Root,
        Child
    }

    public class AggregatorConfig
    {
        public List<TableDefinition> Tables { get; set; }
            = new List<TableDefinition>();

        public static AggregatorConfig Load(string configPath)
        {
            if (!File.Exists(configPath))
            {
                throw new FileNotFoundException(
                    "Aggregator configuration was not found.",
                    configPath);
            }

            XDocument document = XDocument.Load(configPath);

            XElement aggregatorElement =
                document.Root?.Element("aggregator");

            if (aggregatorElement == null)
            {
                throw new InvalidOperationException(
                    "Missing <aggregator> configuration section.");
            }

            XElement tablesElement =
                aggregatorElement.Element("Tables");

            if (tablesElement == null)
            {
                throw new InvalidOperationException(
                    "Missing <Tables> element.");
            }

            var config = new AggregatorConfig();

            foreach (XElement element in tablesElement.Elements("Table"))
            {
                config.Tables.Add(ParseTable(element));
            }

            config.Validate();

            return config;
        }

        private static TableDefinition ParseTable(XElement element)
        {
            string typeValue = (string)element.Attribute("type");

            if (!Enum.TryParse(typeValue, true, out TableType tableType))
            {
                throw new InvalidOperationException(
                    $"Invalid table type '{typeValue}'.");
            }

            var table = new TableDefinition
            {
                Name = RequiredAttribute(element, "name"),
                Type = tableType,

                SourceTable = RequiredAttribute(element, "sourceTable"),
                DestinationTable = RequiredAttribute(element, "destinationTable"),

                Parent = (string)element.Attribute("parent"),

                PrimaryKey = (string)element.Attribute("primaryKey"),
                UniqueKey = (string)element.Attribute("uniqueKey"),

                JoinOperator = "AND"
            };

            XElement joinElement = element.Element("JoinConditions");

            if (joinElement != null)
            {
                table.JoinOperator =
                    ((string)joinElement.Attribute("operator") ?? "AND")
                    .ToUpperInvariant();

                foreach (XElement condition in joinElement.Elements("Condition"))
                {
                    table.JoinConditions.Add(new JoinCondition
                    {
                        ParentColumn = RequiredAttribute(
                            condition, "parentColumn"),

                        ChildColumn = RequiredAttribute(
                            condition, "childColumn")
                    });
                }
            }

            XElement columnsElement = element.Element("Columns");

            if (columnsElement != null)
            {
                foreach (XElement column in columnsElement.Elements("Column"))
                {
                    string source = RequiredAttribute(column, "source");

                    table.Columns.Add(new ColumnMapping
                    {
                        Source = source,

                        // If destination is omitted, use the source name.
                        Destination =
                            (string)column.Attribute("destination") ?? source
                    });
                }
            }

            return table;
        }

        private static string RequiredAttribute(
            XElement element,
            string attributeName)
        {
            string value = (string)element.Attribute(attributeName);

            if (string.IsNullOrWhiteSpace(value))
            {
                throw new InvalidOperationException(
                    $"Element <{element.Name}> requires attribute '{attributeName}'.");
            }

            return value;
        }

        public void Validate()
        {
            var names = new HashSet<string>(
                StringComparer.OrdinalIgnoreCase);

            foreach (var table in Tables)
            {
                if (!names.Add(table.Name))
                {
                    throw new InvalidOperationException(
                        $"Duplicate table definition: {table.Name}");
                }

                if (table.Type == TableType.Child &&
                    string.IsNullOrWhiteSpace(table.Parent))
                {
                    throw new InvalidOperationException(
                        $"Child table '{table.Name}' must define a parent.");
                }

                if (table.JoinOperator != "AND" &&
                    table.JoinOperator != "OR")
                {
                    throw new InvalidOperationException(
                        $"Invalid JoinConditions operator for '{table.Name}'.");
                }

                if (table.JoinConditions.Count > 0 &&
                    string.IsNullOrWhiteSpace(table.Parent))
                {
                    throw new InvalidOperationException(
                        $"Table '{table.Name}' defines JoinConditions but has no parent.");
                }
            }

            foreach (var table in Tables)
            {
                if (!string.IsNullOrWhiteSpace(table.Parent))
                {
                    bool parentExists = Tables.Any(
                        x => x.Name.Equals(
                            table.Parent,
                            StringComparison.OrdinalIgnoreCase));

                    if (!parentExists)
                    {
                        throw new InvalidOperationException(
                            $"Parent '{table.Parent}' for table " +
                            $"'{table.Name}' was not defined.");
                    }
                }
            }
        }

        public List<TableDefinition> GetTablesInDependencyOrder()
        {
            var ordered = new List<TableDefinition>();
            var visited = new HashSet<string>(
                StringComparer.OrdinalIgnoreCase);

            var visiting = new HashSet<string>(
                StringComparer.OrdinalIgnoreCase);

            foreach (var table in Tables)
            {
                Visit(table, visited, visiting, ordered);
            }

            return ordered;
        }

        private void Visit(
            TableDefinition table,
            HashSet<string> visited,
            HashSet<string> visiting,
            List<TableDefinition> ordered)
        {
            if (visited.Contains(table.Name))
                return;

            if (!visiting.Add(table.Name))
            {
                throw new InvalidOperationException(
                    $"Circular table dependency detected at '{table.Name}'.");
            }

            if (!string.IsNullOrWhiteSpace(table.Parent))
            {
                TableDefinition parent = Tables.First(
                    x => x.Name.Equals(
                        table.Parent,
                        StringComparison.OrdinalIgnoreCase));

                Visit(parent, visited, visiting, ordered);
            }

            visiting.Remove(table.Name);
            visited.Add(table.Name);
            ordered.Add(table);
        }
    }

    public class TableDefinition
    {
        public string Name { get; set; }

        public TableType Type { get; set; }

        public string SourceTable { get; set; }

        public string DestinationTable { get; set; }

        public string Parent { get; set; }

        public string PrimaryKey { get; set; }

        public string UniqueKey { get; set; }

        public string JoinOperator { get; set; }

        public List<JoinCondition> JoinConditions { get; set; }
            = new List<JoinCondition>();

        public List<ColumnMapping> Columns { get; set; }
            = new List<ColumnMapping>();
    }

    public class JoinCondition
    {
        public string ParentColumn { get; set; }

        public string ChildColumn { get; set; }
    }

    public class ColumnMapping
    {
        public string Source { get; set; }

        public string Destination { get; set; }
    }
}
```

## 3. C# interfaces for your existing SQLite and SQL Server classes

These interfaces define the small boundary between the aggregator and your existing implementations. They do not implement another database reader or writer.

Add `DatabaseInterfaces.cs`:

```
using System.Data;

namespace DataAggregator
{
    public interface ISqliteReader
    {
        DataTable GetTableData(string sourceTable);
    }

    public interface ISqlServerWriter
    {
        // Create the destination table using the supplied metadata.
        void CreateTable(TableDefinition definition);

        // Insert or update the supplied source data.
        void InsertOrUpdateData(
            TableDefinition definition,
            DataTable data);
    }
}
```

Your existing classes can be connected through small adapter classes, or you can implement these interfaces directly in those classes if you prefer.

For example, the SQL Server adapter should pass the following information to your existing table-creation method:

| Configuration property | Purpose                                   |
| ---------------------- | ----------------------------------------- |
| `DestinationTable`     | SQL Server table name                     |
| `PrimaryKey`           | Primary-key definition                    |
| `UniqueKey`            | Unique-key definition                     |
| `JoinConditions`       | Parent/child column relationship metadata |
| `JoinOperator`         | `AND` or `OR`                             |
| `Columns`              | Source-to-destination column mappings     |

The actual method calls inside the adapter depend on the method signatures already present in your `SQLServer.cs`.

## 4. DataAggregator.cs

This is the main orchestration class. It reads each SQLite table and passes the data and table definition to SQL Server.

```
using System;
using System.Collections.Generic;
using System.Data;

namespace DataAggregator
{
    public class DataAggregator
    {
        private readonly ISqliteReader _sqliteReader;
        private readonly ISqlServerWriter _sqlServerWriter;
        private readonly AggregatorConfig _config;

        public DataAggregator(
            ISqliteReader sqliteReader,
            ISqlServerWriter sqlServerWriter,
            AggregatorConfig config)
        {
            _sqliteReader = sqliteReader
                ?? throw new ArgumentNullException(nameof(sqliteReader));

            _sqlServerWriter = sqlServerWriter
                ?? throw new ArgumentNullException(nameof(sqlServerWriter));

            _config = config
                ?? throw new ArgumentNullException(nameof(config));
        }

        public void Run()
        {
            List<TableDefinition> tables =
                _config.GetTablesInDependencyOrder();

            foreach (TableDefinition table in tables)
            {
                ProcessTable(table);
            }
        }

        private void ProcessTable(TableDefinition table)
        {
            Console.WriteLine(
                $"Processing {table.Name} " +
                $"({table.Type})");

            // 1. Read the source SQLite table.
            DataTable data =
                _sqliteReader.GetTableData(table.SourceTable);

            if (data == null)
            {
                throw new InvalidOperationException(
                    $"SQLite reader returned null for '{table.SourceTable}'.");
            }

            // 2. Create the destination SQL Server table.
            //    JoinConditions are passed as metadata here.
            _sqlServerWriter.CreateTable(table);

            // 3. Insert or update the data.
            //    No SQLite joins or filtering are performed here.
            _sqlServerWriter.InsertOrUpdateData(table, data);

            Console.WriteLine(
                $"Completed {table.Name}: {data.Rows.Count} rows.");
        }
    }
}
```

## 5. Starting the aggregator

For example, your application entry point could look like this:

```
using System;
using System.IO;

namespace DataAggregator
{
    class Program
    {
        static void Main(string[] args)
        {
            try
            {
                string configPath =
                    AppDomain.CurrentDomain.SetupInformation.ConfigurationFile;

                AggregatorConfig config =
                    AggregatorConfig.Load(configPath);

                // Connect your existing implementations here.
                ISqliteReader sqliteReader =
                    CreateSqliteReader();

                ISqlServerWriter sqlServerWriter =
                    CreateSqlServerWriter();

                var aggregator = new DataAggregator(
                    sqliteReader,
                    sqlServerWriter,
                    config);

                aggregator.Run();

                Console.WriteLine("Aggregation completed.");
            }
            catch (Exception ex)
            {
                Console.WriteLine(
                    "Aggregation failed: " + ex);
            }
        }

        private static ISqliteReader CreateSqliteReader()
        {
            // Return an adapter around your existing SQLite class.
            throw new NotImplementedException(
                "Connect your existing SQLite reader here.");
        }

        private static ISqlServerWriter CreateSqlServerWriter()
        {
            // Return an adapter around your existing SQLServer.cs class.
            throw new NotImplementedException(
                "Connect your existing SQL Server writer here.");
        }
    }
}
```

The two factory methods are intentionally left for integration with your actual classes; I don't know their current constructors and method signatures, so I don't want to invent them.

## 6. Example dependency order

Even if the tables appear in a different order in `app.config`, the aggregator will process them according to their parent relationships.

For the example configuration:

TestRunProperty

Property

MOSS

Root

MOSS_Child

Child

MOSS_Child_2

Child

The resulting processing order is:

```
1. TestRunProperty
2. MOSS
3. MOSS_Child
4. MOSS_Child_2
```

## 7. Important design decisions

I recommend keeping these responsibilities separate:

| Component               | Responsibility                             |
| ----------------------- | ------------------------------------------ |
| `app.config`            | Table definitions and relationships        |
| `AggregatorConfig`      | Load and validate configuration            |
| `DataAggregator`        | Determine processing order and orchestrate |
| Existing SQLite class   | Read source tables                         |
| Existing `SQLServer.cs` | Create tables and insert/update records    |

One important point about `JoinConditions`: since the SQLite database has no foreign-key constraints, these conditions are logical metadata supplied by your configuration. They do not automatically create SQL Server foreign-key constraints. Your existing `SQLServer.cs` should decide how to use them during destination table creation.

Also, the current orchestration intentionally reads the complete source `DataTable` for each table. It does not filter rows based on the parent relationship.

## 8. What I need to make the integration exact

The configuration parser and orchestration above establish the design. To give you the final code without placeholders, I need to see the existing method signatures from:

1. Your SQLite class that reads a table into a `DataTable`.
2. Your `SQLServer.cs` table-creation method.
3. Your `SQLServer.cs` insert/update method.

With those methods, I can connect the aggregator directly to your existing implementation without rewriting your database code.











======================
======================
======================














I recommend correcting the design in one important way: do not make `Root`, `Singular`, and `Child` determine whether a table can be a parent. Those are aggregation categories; parent-child relationships are a separate concern.

The corrected design below uses:

- `Root` tables: associated directly with a test run.
- `Singular` tables: independently aggregated; they can also be parents.
- `Child` tables: aggregated through a configured parent.
- `JoinConditions`: supports multiple conditions joined with `AND` or `OR`.
- `KeyColumns`: identifies records for idempotent updates.
- Explicit source-to-destination column mappings.
- A dependency graph so a child can depend on a root, singular, or another child table.

Important: I do not have your actual SQLite table definitions or SDA SQL Server schema. So I can provide a complete, consistent reference implementation, but I cannot honestly call it a drop-in replacement until the real table names, columns, keys, and existing TestRun identity rules are matched. I will mark the assumptions rather than invent your schema.

## 1. Corrected `App.config`

This example assumes:

- .NET Framework 4.8
- SQLite source database
- SQL Server destination database
- The destination has a `TestRun` table with `TestRunId`, `SourceDatabase`, and `SourceTestRunID`.
- Source primary-key values are retained in the destination, so configured key columns can identify corresponding records. If your SDA generates different destination IDs, we should add a source-to-destination key mapping layer instead.

The `aggregator` section is declared so the .NET configuration system accepts it. The code below reads its XML directly.

```

<?xml version="1.0" encoding="utf-8"?>
<configuration>

  <configSections>
    <section name="aggregator"
             type="System.Configuration.IgnoreSection, System.Configuration" />
  </configSections>

  <connectionStrings>
    <add name="SourceSQLite"
         connectionString="Data Source={SOURCE_DB_PATH};Version=3;"
         providerName="System.Data.SQLite" />

    <add name="DestinationSQL"
         connectionString="Data Source=YOUR_SQL_SERVER;Initial Catalog=YOUR_SDA_DATABASE;Integrated Security=True;"
         providerName="System.Data.SqlClient" />
  </connectionStrings>

  <appSettings>
    <add key="CommandTimeoutSeconds" value="120" />
    <add key="BatchSize" value="500" />
  </appSettings>

  <aggregator>

    <!-- Identifies the source test run and its destination record. -->
    <TestRun
        sourceIdentityTable="TestRun"
        sourceIdentityColumn="TestRunID"
        destinationTable="SDA_TestRun"
        destinationIdentityColumn="TestRunId"
        sourceDatabaseColumn="SourceDatabase"
        sourceRunIdColumn="SourceTestRunID" />

    <!-- Common destination metadata columns. -->
    <CommonColumns>
      <Column name="SourceSystem" value="SQLite" />
      <Column name="ImportedBy" value="DataTransferApp" />
      <Column name="ImportDate" value="{UTCNOW}" />
    </CommonColumns>

    <Tables>

      <!-- ROOT TABLE: directly associated with the test run. -->
      <Table
          name="Student"
          type="Root"
          sourceTable="Student"
          destinationTable="SDA_Student"
          sourceAlias="s"
          runFilterColumn="TestRunID"
          keyColumns="StudentID">

        <Columns>
          <Column source="StudentID" destination="StudentID" />
          <Column source="Name" destination="Name" />
          <Column source="Email" destination="Email" />
        </Columns>
      </Table>

      <!-- ROOT TABLE -->
      <Table
          name="Teacher"
          type="Root"
          sourceTable="Teacher"
          destinationTable="SDA_Teacher"
          sourceAlias="t"
          runFilterColumn="TestRunID"
          keyColumns="TeacherID">

        <Columns>
          <Column source="TeacherID" destination="TeacherID" />
          <Column source="Name" destination="Name" />
        </Columns>
      </Table>

      <!-- SINGULAR TABLE: independently aggregated.
           It can also be a parent of another table. -->
      <Table
          name="TestRunProperty"
          type="Singular"
          sourceTable="TestRunProperty"
          destinationTable="SDA_TestRunProperty"
          sourceAlias="trp"
          runFilterColumn="TestRunID"
          keyColumns="TestRunPropertyID">

        <Columns>
          <Column source="TestRunPropertyID" destination="TestRunPropertyID" />
          <Column source="PropertyName" destination="PropertyName" />
          <Column source="PropertyValue" destination="PropertyValue" />
        </Columns>
      </Table>

      <!-- CHILD OF ROOT TABLE -->
      <Table
          name="StudentDetails"
          type="Child"
          sourceTable="StudentDetails"
          destinationTable="SDA_StudentDetails"
          sourceAlias="sd"
          parent="Student"
          joinType="LEFT"
          keyColumns="StudentDetailID">

        <JoinConditions operator="AND">
          <Condition
              leftAlias="sd"
              leftColumn="StudentID"
              rightAlias="s"
              rightColumn="StudentID" />

          <Condition
              leftAlias="sd"
              leftColumn="TestRunID"
              rightAlias="s"
              rightColumn="TestRunID" />
        </JoinConditions>

        <Columns>
          <Column source="StudentDetailID" destination="StudentDetailID" />
          <Column source="StudentID" destination="StudentID" />
          <Column source="Address" destination="Address" />
        </Columns>
      </Table>

      <!-- CHILD OF SINGULAR TABLE -->
      <Table
          name="PropertyDetails"
          type="Child"
          sourceTable="PropertyDetails"
          destinationTable="SDA_PropertyDetails"
          sourceAlias="pd"
          parent="TestRunProperty"
          joinType="LEFT"
          keyColumns="PropertyDetailID">

        <JoinConditions operator="AND">
          <Condition
              leftAlias="pd"
              leftColumn="TestRunPropertyID"
              rightAlias="trp"
              rightColumn="TestRunPropertyID" />
        </JoinConditions>

        <Columns>
          <Column source="PropertyDetailID" destination="PropertyDetailID" />
          <Column source="TestRunPropertyID" destination="TestRunPropertyID" />
          <Column source="Description" destination="Description" />
        </Columns>
      </Table>

      <!-- CHILD OF CHILD: demonstrates deeper relationships. -->
      <Table
          name="StudentAddress"
          type="Child"
          sourceTable="StudentAddress"
          destinationTable="SDA_StudentAddress"
          sourceAlias="sa"
          parent="StudentDetails"
          joinType="LEFT"
          keyColumns="StudentAddressID">

        <JoinConditions operator="AND">
          <Condition
              leftAlias="sa"
              leftColumn="StudentDetailID"
              rightAlias="sd"
              rightColumn="StudentDetailID" />
        </JoinConditions>

        <Columns>
          <Column source="StudentAddressID" destination="StudentAddressID" />
          <Column source="StudentDetailID" destination="StudentDetailID" />
          <Column source="City" destination="City" />
          <Column source="Country" destination="Country" />
        </Columns>
      </Table>

    </Tables>
  </aggregator>

</configuration>

```

How to read the configuration:

- `parent` is optional for `Root` and `Singular`, and required for `Child`.
- A `Singular` table can be a parent.
- A `Child` table can also be a parent.
- `JoinConditions` supports multiple conditions.
- `runFilterColumn` scopes root and singular records to the current source test run.
- `keyColumns` contains destination column names used to identify records for updates. The example assumes source and destination key values match.

The table and column names above are illustrative. Replace them with names from your SQLite database and SDA.

## 2. C# configuration classes

Create `Models/AggregatorConfiguration.cs`.

```

using System.Collections.Generic;

namespace DataAggregator.Models
{
    public class AggregatorConfiguration
    {
        public TestRunDefinition TestRun { get; set; }

        public List<CommonColumn> CommonColumns { get; set; }
            = new List<CommonColumn>();

        public List<TableDefinition> Tables { get; set; }
            = new List<TableDefinition>();
    }

    public class TestRunDefinition
    {
        public string SourceIdentityTable { get; set; }
        public string SourceIdentityColumn { get; set; }

        public string DestinationTable { get; set; }
        public string DestinationIdentityColumn { get; set; }

        public string SourceDatabaseColumn { get; set; }
        public string SourceRunIdColumn { get; set; }
    }

    public class CommonColumn
    {
        public string Name { get; set; }
        public string Value { get; set; }
    }

    public class TableDefinition
    {
        public string Name { get; set; }
        public string Type { get; set; }

        public string SourceTable { get; set; }
        public string DestinationTable { get; set; }

        public string SourceAlias { get; set; }
        public string Parent { get; set; }

        public string JoinType { get; set; }
        public string JoinOperator { get; set; }

        public string RunFilterColumn { get; set; }

        public List<string> KeyColumns { get; set; }
            = new List<string>();

        public List<ColumnMapping> Columns { get; set; }
            = new List<ColumnMapping>();

        public List<JoinCondition> JoinConditions { get; set; }
            = new List<JoinCondition>();
    }

    public class ColumnMapping
    {
        public string Source { get; set; }
        public string Destination { get; set; }
    }

    public class JoinCondition
    {
        public string LeftAlias { get; set; }
        public string LeftColumn { get; set; }

        public string RightAlias { get; set; }
        public string RightColumn { get; set; }
    }
}

```

## 3. Configuration loader

Create `Configuration/ConfigurationLoader.cs`.

```

using System;
using System.Collections.Generic;
using System.Configuration;
using System.IO;
using System.Linq;
using System.Xml.Linq;
using DataAggregator.Models;

namespace DataAggregator.Configuration
{
    public static class ConfigurationLoader
    {
        public static AggregatorConfiguration Load()
        {
            string configPath =
                ConfigurationManager
                    .OpenExeConfiguration(ConfigurationUserLevel.None)
                    .FilePath;

            if (!File.Exists(configPath))
                throw new FileNotFoundException(
                    "Application configuration file not found.",
                    configPath);

            XDocument document = XDocument.Load(configPath);

            XElement root = document.Root?
                .Element("aggregator");

            if (root == null)
                throw new ConfigurationErrorsException(
                    "Missing aggregator configuration section.");

            return Parse(root);
        }

        private static AggregatorConfiguration Parse(XElement root)
        {
            var config = new AggregatorConfiguration();

            XElement testRun = root.Element("TestRun");

            if (testRun == null)
                throw new ConfigurationErrorsException(
                    "Missing TestRun configuration.");

            config.TestRun = new TestRunDefinition
            {
                SourceIdentityTable =
                    Required(testRun, "sourceIdentityTable"),

                SourceIdentityColumn =
                    Required(testRun, "sourceIdentityColumn"),

                DestinationTable =
                    Required(testRun, "destinationTable"),

                DestinationIdentityColumn =
                    Required(testRun, "destinationIdentityColumn"),

                SourceDatabaseColumn =
                    Required(testRun, "sourceDatabaseColumn"),

                SourceRunIdColumn =
                    Required(testRun, "sourceRunIdColumn")
            };

            XElement common = root.Element("CommonColumns");

            if (common != null)
            {
                config.CommonColumns = common
                    .Elements("Column")
                    .Select(x => new CommonColumn
                    {
                        Name = Required(x, "name"),
                        Value = Required(x, "value")
                    })
                    .ToList();
            }

            XElement tables = root.Element("Tables");

            if (tables == null)
                throw new ConfigurationErrorsException(
                    "Missing Tables configuration.");

            config.Tables = tables
                .Elements("Table")
                .Select(ParseTable)
                .ToList();

            Validate(config);

            return config;
        }

        private static TableDefinition ParseTable(XElement element)
        {
            var table = new TableDefinition
            {
                Name = Required(element, "name"),
                Type = Required(element, "type"),

                SourceTable = Required(element, "sourceTable"),
                DestinationTable = Required(element, "destinationTable"),

                SourceAlias = Required(element, "sourceAlias"),

                Parent = (string)element.Attribute("parent"),

                JoinType = (string)element.Attribute("joinType") ?? "INNER",

                RunFilterColumn =
                    (string)element.Attribute("runFilterColumn"),

                KeyColumns = ((string)element.Attribute("keyColumns") ?? "")
                    .Split(new[] { ',' },
                        StringSplitOptions.RemoveEmptyEntries)
                    .Select(x => x.Trim())
                    .ToList()
            };

            XElement conditions = element.Element("JoinConditions");

            if (conditions != null)
            {
                table.JoinOperator =
                    (string)conditions.Attribute("operator") ?? "AND";

                table.JoinConditions = conditions
                    .Elements("Condition")
                    .Select(x => new JoinCondition
                    {
                        LeftAlias = Required(x, "leftAlias"),
                        LeftColumn = Required(x, "leftColumn"),
                        RightAlias = Required(x, "rightAlias"),
                        RightColumn = Required(x, "rightColumn")
                    })
                    .ToList();
            }

            XElement columns = element.Element("Columns");

            if (columns != null)
            {
                table.Columns = columns
                    .Elements("Column")
                    .Select(x => new ColumnMapping
                    {
                        Source = Required(x, "source"),
                        Destination = Required(x, "destination")
                    })
                    .ToList();
            }

            return table;
        }

        private static string Required(
            XElement element,
            string attribute)
        {
            string value = (string)element.Attribute(attribute);

            if (string.IsNullOrWhiteSpace(value))
                throw new ConfigurationErrorsException(
                    $"Missing required attribute '{attribute}'.");

            return value;
        }

        private static void Validate(AggregatorConfiguration config)
        {
            var tables = config.Tables.ToDictionary(
                x => x.Name,
                StringComparer.OrdinalIgnoreCase);

            foreach (var table in config.Tables)
            {
                if (!new[] { "Root", "Singular", "Child" }
                    .Contains(table.Type, StringComparer.OrdinalIgnoreCase))
                {
                    throw new ConfigurationErrorsException(
                        $"Invalid table type '{table.Type}' for {table.Name}.");
                }

                if (table.Type.Equals(
                    "Child", StringComparison.OrdinalIgnoreCase))
                {
                    if (string.IsNullOrWhiteSpace(table.Parent))
                        throw new ConfigurationErrorsException(
                            $"Child table {table.Name} requires a parent.");

                    if (!tables.ContainsKey(table.Parent))
                        throw new ConfigurationErrorsException(
                            $"Parent '{table.Parent}' for {table.Name} does not exist.");

                    if (table.JoinConditions.Count == 0)
                        throw new ConfigurationErrorsException(
                            $"Child table {table.Name} requires join conditions.");

                    if (!new[] { "INNER", "LEFT" }
                        .Contains(table.JoinType.ToUpperInvariant()))
                    {
                        throw new ConfigurationErrorsException(
                            $"Unsupported join type '{table.JoinType}'.");
                    }

                    if (!new[] { "AND", "OR" }
                        .Contains((table.JoinOperator ?? "AND").ToUpperInvariant()))
                    {
                        throw new ConfigurationErrorsException(
                            $"Unsupported join operator for {table.Name}.");
                    }
                }

                if (table.Columns.Count == 0)
                    throw new ConfigurationErrorsException(
                        $"Table {table.Name} has no column mappings.");

                if (table.KeyColumns.Count == 0)
                    throw new ConfigurationErrorsException(
                        $"Table {table.Name} has no key columns.");
            }

            // Detect cycles in parent relationships.
            foreach (var table in config.Tables)
            {
                var visited = new HashSet<string>(
                    StringComparer.OrdinalIgnoreCase);

                var current = table;

                while (!string.IsNullOrWhiteSpace(current.Parent))
                {
                    if (!visited.Add(current.Name))
                        throw new ConfigurationErrorsException(
                            $"Circular table relationship detected at {current.Name}.");

                    current = tables[current.Parent];
                }
            }
        }
    }
}

```

This loader deliberately does not assume that only root tables can be parents. It validates that the referenced parent exists and that the relationship graph has no cycles.

## 4. SQL identifier validation

Never concatenate arbitrary configuration values into SQL without validating them. SQL parameters protect values, but table names, column names, and aliases need identifier validation.

Create `Data/SqlIdentifier.cs`.

```

using System;
using System.Text.RegularExpressions;

namespace DataAggregator.Data
{
    public static class SqlIdentifier
    {
        private static readonly Regex ValidIdentifier =
            new Regex(@"^[A-Za-z_][A-Za-z0-9_]*$");

        public static string Quote(string identifier)
        {
            if (string.IsNullOrWhiteSpace(identifier) ||
                !ValidIdentifier.IsMatch(identifier))
            {
                throw new ArgumentException(
                    $"Invalid SQL identifier: {identifier}");
            }

            return "[" + identifier + "]";
        }

        public static string Qualified(string alias, string column)
        {
            return Quote(alias) + "." + Quote(column);
        }
    }
}

```

This intentionally supports simple identifiers such as `StudentDetails` and `StudentID`. If your actual database uses schema-qualified names such as `dbo.SDA_Student`, extend the validator to handle schema and table as separate parts.

## 5. SQLite source reader and query builder

The query builder handles the important relationship rule:

- A root or singular table is read independently, optionally filtered by its `runFilterColumn`.
- A child table joins to its configured parent.
- If that parent is itself a child, the query follows the parent chain until it reaches a root or singular table.
- Every join uses the conditions configured for that relationship.

Create `Data/SQLiteSourceReader.cs`.

```

using System;
using System.Collections.Generic;
using System.Data;
using System.Data.SQLite;
using System.Linq;
using DataAggregator.Models;

namespace DataAggregator.Data
{
    public class SQLiteSourceReader
    {
        private readonly string connectionString;

        public SQLiteSourceReader(string connectionString)
        {
            this.connectionString = connectionString;
        }

        public object GetSourceRunId(TestRunDefinition definition)
        {
            string sql =
                "SELECT " +
                SqlIdentifier.Quote(definition.SourceIdentityColumn) +
                " FROM " +
                SqlIdentifier.Quote(definition.SourceIdentityTable) +
                " LIMIT 1";

            using (var connection = new SQLiteConnection(connectionString))
            using (var command = new SQLiteCommand(sql, connection))
            {
                connection.Open();

                object result = command.ExecuteScalar();

                if (result == null || result == DBNull.Value)
                    throw new InvalidOperationException(
                        "Could not identify the source TestRun.");

                return result;
            }
        }

        public DataTable ReadTable(
            TableDefinition table,
            IReadOnlyDictionary<string, TableDefinition> definitions,
            object sourceRunId)
        {
            string sql = BuildSelect(table, definitions);

            using (var connection = new SQLiteConnection(connectionString))
            using (var command = new SQLiteCommand(sql, connection))
            using (var adapter = new SQLiteDataAdapter(command))
            {
                connection.Open();

                if (!string.IsNullOrWhiteSpace(table.RunFilterColumn) ||
                    HasAncestorRunFilter(table, definitions))
                {
                    command.Parameters.AddWithValue(
                        "@sourceRunId", sourceRunId);
                }

                var result = new DataTable(table.Name);

                adapter.Fill(result);

                return result;
            }
        }

        private string BuildSelect(
            TableDefinition table,
            IReadOnlyDictionary<string, TableDefinition> definitions)
        {
            var selectColumns = table.Columns.Select(column =>
                SqlIdentifier.Qualified(
                    table.SourceAlias,
                    column.Source) +
                " AS " +
                SqlIdentifier.Quote(column.Destination));

            string sql =
                "SELECT " + string.Join(", ", selectColumns) +
                " FROM " +
                SqlIdentifier.Quote(table.SourceTable) +
                " AS " +
                SqlIdentifier.Quote(table.SourceAlias);

            var whereConditions = new List<string>();

            var current = table;

            while (!string.IsNullOrWhiteSpace(current.Parent))
            {
                var parent = definitions[current.Parent];

                string joinConditions = string.Join(
                    " " + (current.JoinOperator ?? "AND") + " ",
                    current.JoinConditions.Select(condition =>
                        SqlIdentifier.Qualified(
                            condition.LeftAlias,
                            condition.LeftColumn) +
                        " = " +
                        SqlIdentifier.Qualified(
                            condition.RightAlias,
                            condition.RightColumn)));

                sql +=
                    " " + current.JoinType.ToUpperInvariant() +
                    " JOIN " +
                    SqlIdentifier.Quote(parent.SourceTable) +
                    " AS " +
                    SqlIdentifier.Quote(parent.SourceAlias) +
                    " ON (" + joinConditions + ")";

                current = parent;
            }

            // Apply the TestRun filter to every table in the
            // relationship chain that declares one.
            current = table;

            while (current != null)
            {
                if (!string.IsNullOrWhiteSpace(current.RunFilterColumn))
                {
                    whereConditions.Add(
                        SqlIdentifier.Qualified(
                            current.SourceAlias,
                            current.RunFilterColumn) +
                        " = @sourceRunId");
                }

                current = string.IsNullOrWhiteSpace(current.Parent)
                    ? null
                    : definitions[current.Parent];
            }

            if (whereConditions.Count > 0)
            {
                sql += " WHERE " +
                    string.Join(" AND ", whereConditions);
            }

            return sql;
        }

        private bool HasAncestorRunFilter(
            TableDefinition table,
            IReadOnlyDictionary<string, TableDefinition> definitions)
        {
            var current = table;

            while (current != null)
            {
                if (!string.IsNullOrWhiteSpace(current.RunFilterColumn))
                    return true;

                current = string.IsNullOrWhiteSpace(current.Parent)
                    ? null
                    : definitions[current.Parent];
            }

            return false;
        }
    }
}

```

Important limitation to understand: this version selects the mapped columns from the current table only. Parent tables are used to filter and relate the child rows, not to copy parent columns into the child destination. That is normally the right behavior for a normalized destination.

Also, the example uses `=` comparisons and a single `@sourceRunId` parameter. If your real joins require `IS NULL`, inequalities, expressions, or joins involving more complex predicates, those should be explicitly added to the configuration model and SQL builder rather than placed in free-form SQL.

## 6. SQL Server destination writer

This version performs an update first and inserts only when no matching record exists. It avoids relying on `MERGE`, but you should still create a unique index on the configured logical key to protect against concurrent imports.

Create `Data/SqlServerDestinationWriter.cs`.

```

using System;
using System.Collections.Generic;
using System.Data;
using System.Data.SqlClient;
using System.Linq;
using DataAggregator.Models;

namespace DataAggregator.Data
{
    public class SqlServerDestinationWriter
    {
        private readonly string connectionString;

        public SqlServerDestinationWriter(string connectionString)
        {
            this.connectionString = connectionString;
        }

        public int GetOrCreateTestRun(
            TestRunDefinition definition,
            string sourceDatabase,
            object sourceRunId)
        {
            string destinationTable =
                SqlIdentifier.Quote(definition.DestinationTable);

            string destinationId =
                SqlIdentifier.Quote(definition.DestinationIdentityColumn);

            string sourceDbColumn =
                SqlIdentifier.Quote(definition.SourceDatabaseColumn);

            string sourceRunColumn =
                SqlIdentifier.Quote(definition.SourceRunIdColumn);

            string selectSql =
                $"SELECT {destinationId} FROM {destinationTable} " +
                $"WHERE {sourceDbColumn} = @sourceDatabase " +
                $"AND {sourceRunColumn} = @sourceRunId";

            using (var connection = new SqlConnection(connectionString))
            {
                connection.Open();

                using (var transaction = connection.BeginTransaction())
                {
                    using (var select = new SqlCommand(
                        selectSql, connection, transaction))
                    {
                        select.Parameters.AddWithValue(
                            "@sourceDatabase", sourceDatabase);

                        select.Parameters.AddWithValue(
                            "@sourceRunId", sourceRunId);

                        object existing = select.ExecuteScalar();

                        if (existing != null && existing != DBNull.Value)
                        {
                            transaction.Commit();
                            return Convert.ToInt32(existing);
                        }
                    }

                    string insertSql =
                        $"INSERT INTO {destinationTable} " +
                        $"({sourceDbColumn}, {sourceRunColumn}) " +
                        "VALUES (@sourceDatabase, @sourceRunId); " +
                        "SELECT CAST(SCOPE_IDENTITY() AS INT);";

                    using (var insert = new SqlCommand(
                        insertSql, connection, transaction))
                    {
                        insert.Parameters.AddWithValue(
                            "@sourceDatabase", sourceDatabase);

                        insert.Parameters.AddWithValue(
                            "@sourceRunId", sourceRunId);

                        int id = Convert.ToInt32(
                            insert.ExecuteScalar());

                        transaction.Commit();

                        return id;
                    }
                }
            }
        }

        public void Upsert(
            string destinationTable,
            DataRow sourceRow,
            IEnumerable<string> keyColumns,
            int testRunId,
            IEnumerable<CommonColumn> commonColumns)
        {
            var values = new Dictionary<string, object>(
                StringComparer.OrdinalIgnoreCase);

            foreach (DataColumn column in sourceRow.Table.Columns)
            {
                values[column.ColumnName] =
                    sourceRow[column] ?? DBNull.Value;
            }

            // The destination TestRunId is managed by the aggregator.
            values["TestRunId"] = testRunId;

            foreach (var common in commonColumns)
            {
                values[common.Name] = ResolveCommonValue(common.Value);
            }

            var keys = keyColumns.ToList();

            // Include TestRunId in the logical identity of each
            // run-scoped record.
            if (values.ContainsKey("TestRunId") &&
                !keys.Contains(
                    "TestRunId",
                    StringComparer.OrdinalIgnoreCase))
            {
                keys.Add("TestRunId");
            }

            foreach (string key in keys)
            {
                if (!values.ContainsKey(key))
                    throw new InvalidOperationException(
                        $"Key column '{key}' is missing from " +
                        $"destination values for {destinationTable}.");
            }

            string table = SqlIdentifier.Quote(destinationTable);

            var nonKeys = values.Keys
                .Where(x => !keys.Contains(
                    x, StringComparer.OrdinalIgnoreCase))
                .ToList();

            using (var connection = new SqlConnection(connectionString))
            {
                connection.Open();

                using (var transaction = connection.BeginTransaction())
                {
                    int updated = 0;

                    if (nonKeys.Count > 0)
                    {
                        string updateSql =
                            "UPDATE " + table + " SET " +
                            string.Join(", ", nonKeys.Select(
                                x => SqlIdentifier.Quote(x) +
                                     " = @v_" + x)) +
                            " WHERE " +
                            string.Join(" AND ", keys.Select(
                                x => SqlIdentifier.Quote(x) +
                                     " = @v_" + x));

                        using (var command = new SqlCommand(
                            updateSql, connection, transaction))
                        {
                            AddParameters(command, values);

                            updated = command.ExecuteNonQuery();
                        }
                    }

                    if (updated == 0)
                    {
                        string insertSql =
                            "INSERT INTO " + table +
                            " (" +
                            string.Join(", ", values.Keys.Select(
                                SqlIdentifier.Quote)) +
                            ") VALUES (" +
                            string.Join(", ", values.Keys.Select(
                                x => "@v_" + x)) +
                            ")";

                        using (var command = new SqlCommand(
                            insertSql, connection, transaction))
                        {
                            AddParameters(command, values);
                            command.ExecuteNonQuery();
                        }
                    }

                    transaction.Commit();
                }
            }
        }

        private static void AddParameters(
            SqlCommand command,
            IDictionary<string, object> values)
        {
            foreach (var item in values)
            {
                command.Parameters.AddWithValue(
                    "@v_" + item.Key,
                    item.Value ?? DBNull.Value);
            }
        }

        private static object ResolveCommonValue(string value)
        {
            if (string.Equals(
                value, "{UTCNOW}",
                StringComparison.OrdinalIgnoreCase))
            {
                return DateTime.UtcNow;
            }

            return value;
        }
    }
}

```

A few important notes about this writer:

1. It assumes the destination table has a `TestRunId` column. If some tables are not run-scoped, add an explicit `associateWithTestRun` setting rather than injecting that column into every table.
2. It assumes `keyColumns` are destination column names and that their values are present in the mapped source data.
3. The update/insert sequence is safe for a single importer transaction, but two simultaneous importers can still race. A unique constraint and duplicate-key retry handling are needed for concurrent imports.
4. The `CommonColumns` example assumes those metadata columns exist in every configured destination table. If they do not, configure them per table or validate destination schemas before importing.

## 7. Aggregation engine

Create `Services/DataAggregatorService.cs`.

The engine sorts tables by dependency, so a parent is processed before its children. It does not care whether the parent is `Root`, `Singular`, or `Child`.

```

using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using DataAggregator.Data;
using DataAggregator.Models;

namespace DataAggregator.Services
{
    public class DataAggregatorService
    {
        private readonly AggregatorConfiguration config;
        private readonly SQLiteSourceReader sourceReader;
        private readonly SqlServerDestinationWriter destinationWriter;

        private readonly Dictionary<string, TableDefinition> definitions;

        public DataAggregatorService(
            AggregatorConfiguration config,
            string sqliteConnectionString,
            string sqlServerConnectionString)
        {
            this.config = config;

            sourceReader =
                new SQLiteSourceReader(sqliteConnectionString);

            destinationWriter =
                new SqlServerDestinationWriter(sqlServerConnectionString);

            definitions = config.Tables.ToDictionary(
                x => x.Name,
                StringComparer.OrdinalIgnoreCase);
        }

        public void Aggregate(string sourceDatabase)
        {
            Console.WriteLine("Starting aggregation...");
            Console.WriteLine("Source: " + sourceDatabase);

            object sourceRunId =
                sourceReader.GetSourceRunId(config.TestRun);

            int destinationTestRunId =
                destinationWriter.GetOrCreateTestRun(
                    config.TestRun,
                    sourceDatabase,
                    sourceRunId);

            Console.WriteLine(
                $"Destination TestRunId: {destinationTestRunId}");

            foreach (var table in GetProcessingOrder())
            {
                Console.WriteLine(
                    $"Aggregating {table.Name} ({table.Type})...");

                DataTable rows = sourceReader.ReadTable(
                    table,
                    definitions,
                    sourceRunId);

                foreach (DataRow row in rows.Rows)
                {
                    destinationWriter.Upsert(
                        table.DestinationTable,
                        row,
                        table.KeyColumns,
                        destinationTestRunId,
                        config.CommonColumns);
                }

                Console.WriteLine(
                    $"Completed {table.Name}: {rows.Rows.Count} records.");
            }

            Console.WriteLine("Aggregation completed.");
        }

        private List<TableDefinition> GetProcessingOrder()
        {
            var result = new List<TableDefinition>();

            var visited = new HashSet<string>(
                StringComparer.OrdinalIgnoreCase);

            var visiting = new HashSet<string>(
                StringComparer.OrdinalIgnoreCase);

            foreach (var table in config.Tables)
            {
                Visit(table, visited, visiting, result);
            }

            return result;
        }

        private void Visit(
            TableDefinition table,
            HashSet<string> visited,
            HashSet<string> visiting,
            List<TableDefinition> result)
        {
            if (visited.Contains(table.Name))
                return;

            if (!visiting.Add(table.Name))
                throw new InvalidOperationException(
                    $"Circular relationship at {table.Name}.");

            if (!string.IsNullOrWhiteSpace(table.Parent))
            {
                Visit(
                    definitions[table.Parent],
                    visited,
                    visiting,
                    result);
            }

            visiting.Remove(table.Name);
            visited.Add(table.Name);
            result.Add(table);
        }
    }
}

```

## 8. Application entry point

Create `Program.cs`.

```

using System;
using System.Configuration;
using DataAggregator.Configuration;
using DataAggregator.Services;

namespace DataAggregator
{
    internal class Program
    {
        private static int Main(string[] args)
        {
            try
            {
                if (args.Length < 1)
                {
                    Console.WriteLine(
                        "Usage: DataAggregator.exe <SQLiteDatabasePath>");

                    return 1;
                }

                string sourceDatabase = args[0];

                if (!System.IO.File.Exists(sourceDatabase))
                {
                    Console.WriteLine(
                        "Source database does not exist: " +
                        sourceDatabase);

                    return 1;
                }

                var config = ConfigurationLoader.Load();

                string sqliteConnectionString =
                    ConfigurationManager
                        .ConnectionStrings["SourceSQLite"]
                        .ConnectionString
                        .Replace(
                            "{SOURCE_DB_PATH}",
                            sourceDatabase);

                string sqlServerConnectionString =
                    ConfigurationManager
                        .ConnectionStrings["DestinationSQL"]
                        .ConnectionString;

                var service = new DataAggregatorService(
                    config,
                    sqliteConnectionString,
                    sqlServerConnectionString);

                service.Aggregate(
                    System.IO.Path.GetFullPath(sourceDatabase));

                return 0;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine(
                    "Aggregation failed: " + ex);

                return 2;
            }
        }
    }
}

```

Run it with:

```
DataAggregator.exe "C:\TestResults\test-results.db"
```

## 9. Required destination database assumptions

The example expects a destination test-run table similar to this:

```
CREATE TABLE SDA_TestRun
(
    TestRunId INT IDENTITY(1,1) PRIMARY KEY,
    SourceDatabase NVARCHAR(1000) NOT NULL,
    SourceTestRunID NVARCHAR(255) NOT NULL,

    CONSTRAINT UQ_SDA_TestRun_Source
        UNIQUE (SourceDatabase, SourceTestRunID)
);
```

The example also assumes that destination tables have a `TestRunId` column and that the configured key columns exist.

For example:

```
CREATE TABLE SDA_Student
(
    StudentID INT NOT NULL,
    TestRunId INT NOT NULL,
    Name NVARCHAR(255),
    Email NVARCHAR(255),

    CONSTRAINT UQ_SDA_Student
        UNIQUE (TestRunId, StudentID)
);
```

For a child table:

```
CREATE TABLE SDA_StudentDetails
(
    StudentDetailID INT NOT NULL,
    TestRunId INT NOT NULL,
    StudentID INT NOT NULL,
    Address NVARCHAR(500),

    CONSTRAINT UQ_SDA_StudentDetails
        UNIQUE (TestRunId, StudentDetailID)
);
```

These are examples, not instructions to change your existing SDA schema without checking its current keys and relationships.

## 10. Project structure

I would organize the code like this:

```
DataAggregator
│
├── App.config
├── Program.cs
│
├── Models
│   └── AggregatorConfiguration.cs
│
├── Configuration
│   └── ConfigurationLoader.cs
│
├── Data
│   ├── SqlIdentifier.cs
│   ├── SQLiteSourceReader.cs
│   └── SqlServerDestinationWriter.cs
│
└── Services
    └── DataAggregatorService.cs
```

Install the required NuGet packages:

```
Install-Package System.Data.SQLite.Core
Install-Package System.Configuration.ConfigurationManager
```

`System.Data.SqlClient` is available in the .NET Framework 4.8 environment.

## 11. How this design addresses your original requirements

| Requirement                        | Implementation                                                                           |
| ---------------------------------- | ---------------------------------------------------------------------------------------- |
| Generalize TestRunProperty         | It is configured as a `Singular` table                                                   |
| Support additional singular tables | Add another `Table` entry                                                                |
| Root tables                        | Use `type="Root"`                                                                        |
| Child tables                       | Use `type="Child"` and specify `parent`                                                  |
| Singular table can be a parent     | Supported                                                                                |
| Child table can be a parent        | Supported                                                                                |
| Multiple join conditions           | Supported through `JoinConditions`                                                       |
| Historical reprocessing            | Existing TestRun is found by source identity; records are updated or inserted            |
| SUT serial number                  | Add it as a configured table/column mapping once its source is identified                |
| CSC model/version                  | Add a dedicated mapping once the source fields and destination structure are established |
| HIC lookup per test run            | Configure it as a run-scoped table rather than a global singleton                        |

## 12. Important changes I would make before production

There are four areas I would not consider finished yet:

A. Source and destination key mapping

The current example assumes source keys and destination keys have matching values. If SQL Server generates its own IDs, you need a mapping table such as:

```
SourceRecordMap
---------------
TestRunId
SourceTable
SourcePrimaryKey
DestinationPrimaryKey
```

This is particularly important when a child table must reference a parent whose destination ID differs from its SQLite ID.

B. Multiple join conditions

The implementation supports multiple conditions combined with one configured operator (`AND` or `OR`). If you need expressions such as:

```
ON (A.ID = B.ID OR A.AlternateID = B.ID)
AND A.TestRunID = B.TestRunID
```

then the configuration needs nested condition groups. The simple flat condition list does not support mixed AND/OR precedence safely.

C. Historical source identity

Using the full source database path as `SourceDatabase` can cause duplicate TestRun records if the same database is moved to a different directory. A stable source identifier or content/run identity should be used instead.

D. Transactions and performance

The sample writes one record at a time. For large historical imports, use batched writes and a transaction strategy that covers a complete table or test run. Also add destination unique constraints and retry handling for concurrent imports.

## 13. What I need to make this match your actual project

The code above establishes the configuration and aggregation architecture, but I would not replace your current implementation with it without reconciling the real schema.

The most useful next step is to work from your actual SQLite schema and existing SDA destination schema. In particular, I need to verify:

1. The source tables and their columns, including primary-key candidates.
2. The actual existing `TestRun` and `TestRunProperty` structures.
3. The destination table keys and whether SQL Server generates new IDs.
4. The original `joinCondition` definitions, especially the `Competition` and `CompetitionResults` relationships.

With those details, I can adapt this into a compilable implementation that preserves your existing aggregation behavior, rather than requiring you to redesign your database around illustrative table names.
