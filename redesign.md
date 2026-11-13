Based on your lead's original direction, I would make a fairly significant improvement to this configuration. The current `app.config` has a good starting separation between test-run tables, root tables, and child tables, but it has one major architectural problem:

It treats `TestRunProperty` as a special type of table, even though the lead wants it to be just one of several standalone (singular) tables that the aggregator can process.

I would refactor the design around three categories:

1. Test-run metadata: Information needed to identify and establish the test run.
2. Singular tables: Independent tables that can be aggregated without following the message parent/child relationship.
3. Relational tables: Root and child tables that follow the existing parent/child aggregation model.

There is also an important distinction: `TestRunID` is not necessarily the same thing as the source database's primary key. You should preserve the original source primary key and its mapping to the SDA destination.

## 1. Problems with the current app.config

| Current configuration                 | Problem                                                    | Proposed improvement                                        |
| ------------------------------------- | ---------------------------------------------------------- | ----------------------------------------------------------- |
| `TestRunTable1`, `TestRunTable2`      | Artificial numbering and duplicate configuration structure | Use a collection of named table definitions                 |
| `TestRunPropertyTableName`            | Special treatment of one table                             | Generic `sourceTable`                                       |
| `TestRunPropertyDestinationTableName` | Special treatment of destination                           | Generic `destinationTable`                                  |
| `TestRunPropertyTestDateColumnName`   | Hardcoded concept in generic configuration                 | Configure only if required for a specific operation         |
| `TestRunPropertyTestLineColumnName`   | Same problem                                               | Use generic column mapping                                  |
| `TestRunPropertyColumns`              | Specific to TestRunProperty                                | Generic source/destination column mapping                   |
| `TestRunPropertyDestinationColumns`   | Duplicate abstraction                                      | Represent mappings as individual column pairs               |
| `CommonHeaders`                       | Global behavior is mixed with table configuration          | Keep common metadata centralized, but apply it consistently |
| `RootTables` / `ChildTables`          | Reasonable existing relational model                       | Preserve this model separately                              |

One additional concern: the current configuration uses `value` for a list of columns, while `joinCondition` contains SQL expressions. This makes the configuration difficult to validate and potentially difficult to extend.

## 2. My proposed app.config structure

I would use a generic `<SingularTables>` collection and keep the relational aggregation configuration separate.

Here is how I would redesign your configuration:

```

<?xml version="1.0" encoding="utf-8"?>

<configuration>

  <appSettings>
    <add key="AnalysisServer" value="MSSQLServerName" />
    <add key="AnalysisDatabaseName" value="MSSQLDatabaseName" />
  </appSettings>

  <DataAggregator>

    <!-- Common metadata applied to aggregated records -->
    <CommonHeaders
        value="SourceSystem,ImportedBy,ImportDate"
        headerValues="SQLite,DataTransferApp,{UTCNOW}" />

    <!-- Identifies the source test run.
         References a table defined in SingularTables. -->
    <TestRunIdentity
        table="TestRunProperty"
        sourceKey="TestRunID" />

    <!-- ================================= -->
    <!-- SINGULAR TABLES                   -->
    <!-- ================================= -->

    <SingularTables>

      <Table name="TestRunProperty"
             sourceTable="TestRunProperty"
             destinationTable="TestRunProperty"
             keyColumns="TestRunID">

        <Columns>
          <Column source="TestRunID" destination="TestRunID" />
          <Column source="TestDate" destination="TestDate" />
          <Column source="TestLine" destination="TestLine" />
          <Column source="SUTSN" destination="SUTSN" />
        </Columns>

      </Table>

      <Table name="HICLookup"
             sourceTable="HICLookup"
             destinationTable="TestRunHICLookup"
             keyColumns="TestRunID,HICCode">

        <Columns>
          <Column source="HICCode" destination="HICCode" />
          <Column source="Description" destination="Description" />
        </Columns>

      </Table>

      <Table name="CSC"
             sourceTable="CSC"
             destinationTable="TestRunCSC"
             keyColumns="TestRunID,CSCId">

        <Columns>
          <Column source="CSCId" destination="CSCId" />
          <Column source="Model" destination="Model" />
          <Column source="Version" destination="Version" />
        </Columns>

      </Table>

      <Table name="AnotherTable"
             sourceTable="AnotherTable"
             destinationTable="AnotherTable"
             keyColumns="TestRunID,ID">

        <Columns>
          <Column source="ID" destination="ID" />
          <Column source="Name" destination="Name" />
        </Columns>

      </Table>

    </SingularTables>

    <!-- ================================= -->
    <!-- RELATIONAL TABLES                 -->
    <!-- ================================= -->

    <RelationalTables>

      <RootTables>

        <Table name="Student"
               sourceTable="Student"
               destinationTable="StudentReport"
               alias="s"
               parent="TestRun"
               joinType="INNER"
               joinCondition="tr.TestRunID=s.TestRunID">

          <Columns>
            <Column source="StudentID" destination="StudentID" />
            <Column source="FirstName" destination="FirstName" />
            <Column source="LastName" destination="LastName" />
          </Columns>

        </Table>

        <Table name="Teacher"
               sourceTable="Teacher"
               destinationTable="TeacherReport"
               alias="t"
               parent="TestRun"
               joinType="INNER"
               joinCondition="tr.TestRunID=t.TestRunID">

          <Columns>
            <Column source="TeacherID" destination="TeacherID" />
            <Column source="Name" destination="Name" />
            <Column source="Email" destination="Email" />
          </Columns>

        </Table>

      </RootTables>

      <ChildTables>

        <Table name="StudentDetails"
               sourceTable="StudentDetails"
               destinationTable="StudentDetails"
               alias="sd"
               parent="Student"
               joinType="LEFT"
               joinCondition="s.StudentID=sd.StudentID">

          <Columns>
            <Column source="Email" destination="Email" />
            <Column source="Phone" destination="Phone" />
            <Column source="Address" destination="Address" />
          </Columns>

        </Table>

        <Table name="CompetitionResults"
               sourceTable="CompetitionResults"
               destinationTable="CompetitionResults"
               alias="cr"
               parent="Student"
               joinType="LEFT"
               joinCondition="s.StudentID=cr.StudentID">

          <Columns>
            <Column source="CompetitionID" destination="CompetitionID" />
            <Column source="Score" destination="Score" />
            <Column source="Rank" destination="Rank" />
          </Columns>

        </Table>

        <Table name="Competition"
               sourceTable="Competition"
               destinationTable="Competition"
               alias="c"
               parent="CompetitionResults"
               joinType="LEFT"
               joinCondition="cr.CompetitionID=c.CompetitionID">

          <Columns>
            <Column source="CompetitionName" destination="CompetitionName" />
            <Column source="CompetitionDate" destination="CompetitionDate" />
          </Columns>

        </Table>

      </ChildTables>

    </RelationalTables>

  </DataAggregator>

</configuration>

```

This is a proposed configuration model, not a drop-in replacement for your current file. Your existing custom configuration sections will need to be registered and implemented in C#.

### Why this is better

1\. TestRunProperty is no longer a special configuration structure.

It is simply:

```
<Table name="TestRunProperty" ...>
```

The same configuration mechanism handles HIC, CSC, and future standalone tables.

2\. Test-run identification is separate from table aggregation.

```
<TestRunIdentity
    table="TestRunProperty"
    sourceKey="TestRunID" />
```

The aggregator knows which table and key identify a test run without requiring every singular table to have special parsing logic.

3\. Column mappings are generic.

Instead of maintaining separate comma-separated lists:

```
value="TestRunID,TestDate,TestLine"
```

you explicitly define source and destination mappings.

This also makes it easier to support different column names between SQLite and SQL Server.

4\. Root/child relationships remain separate.

Your existing relational aggregation mechanism does not need to be rewritten just because you are making singular-table aggregation more flexible.

One detail to verify: I used `HICLookup`, `CSC`, and `SUTSN` as illustrative source names. These must be replaced with the actual source database schema. Also, if CSC or HIC records already contain `TestRunID`, the aggregator must verify that it matches the current run rather than blindly adding another value.

## 3. How I would refactor the C# code

The most important change is to stop writing table-specific code such as:

```
if (tableName == "TestRunProperty")
{
    // Special parsing
}
else if (tableName == "AnotherTable")
{
    // Another special implementation
}
```

Instead, create a generic aggregation pipeline.

### A. Define configuration models

For example:

```
public class TableDefinition
{
    public string Name { get; set; }
    public string SourceTable { get; set; }
    public string DestinationTable { get; set; }

    public List<string> KeyColumns { get; set; }

    public List<ColumnMapping> Columns { get; set; }
}

public class ColumnMapping
{
    public string Source { get; set; }
    public string Destination { get; set; }
}

public class TestRunIdentity
{
    public string Table { get; set; }
    public string SourceKey { get; set; }
}
```

You can use the same `TableDefinition` for `TestRunProperty`, HIC, CSC, and other singular tables.

### B. Create a generic singular-table aggregator

```
public void AggregateSingularTables(
    SQLiteConnection sourceConnection,
    SqlConnection destinationConnection,
    IEnumerable<TableDefinition> tables,
    long testRunId)
{
    foreach (var table in tables)
    {
        var records = ReadSourceTable(
            sourceConnection,
            table);

        foreach (var record in records)
        {
            var destinationRecord = MapColumns(
                record,
                table.Columns);

            destinationRecord["TestRunID"] = testRunId;

            UpsertRecord(
                destinationConnection,
                table.DestinationTable,
                destinationRecord,
                table.KeyColumns);
        }
    }
}
```

This is illustrative; the actual method signatures should match your current implementation.

Notice what happens here:

- No special handling for `TestRunProperty`.
- No special handling for HIC.
- No special handling for CSC.
- New singular tables can be added through configuration.
- Existing records can be updated through the same mechanism.

One important implementation detail: `TestRunID` should only be injected into the destination when it is not already mapped or when the destination schema requires it. Avoid overwriting a source value without validating its relationship to the current run.

### C. Separate the test-run identification logic

Your aggregator should first establish the identity of the test run.

For example:

```
public long GetOrCreateTestRun(
    SQLiteConnection sourceConnection,
    SqlConnection destinationConnection,
    TestRunIdentity identity)
{
    // Read the configured identity table.
    // Extract the source test-run key.
    // Find the corresponding SDA test run.
    // Create it if it does not exist.
    // Return the existing or newly created SDA TestRunID.
}
```

This method is important because the source `TestRunID` and destination SDA `TestRunID` might not be identical.

Maintain a reliable mapping between them.

### D. Keep relational aggregation independent

Your existing parent/child processing should remain in its own method:

```
public void AggregateRelationalTables(
    SQLiteConnection sourceConnection,
    SqlConnection destinationConnection,
    RelationalTableConfiguration configuration,
    long testRunId)
{
    // Existing root and child aggregation logic.
}
```

The overall workflow becomes:

```
public void AggregateDatabase(string sourceDatabase)
{
    using (var source = OpenSQLite(sourceDatabase))
    using (var destination = OpenSqlServer())
    {
        var testRunId = GetOrCreateTestRun(
            source,
            destination,
            configuration.TestRunIdentity);

        AggregateSingularTables(
            source,
            destination,
            configuration.SingularTables,
            testRunId);

        AggregateRelationalTables(
            source,
            destination,
            configuration.RelationalTables,
            testRunId);
    }
}
```

This is the separation I would aim for.

## 4. Important: Design for historical reprocessing now

Your lead specifically mentioned that the future background agent must be able to process old databases.

I would introduce a processing mode in the C# application:

```
public enum AggregationMode
{
    NewTestRun,
    ReprocessExisting
}
```

Then the aggregator can be invoked in either mode:

```
public void AggregateDatabase(
    string sourceDatabase,
    AggregationMode mode)
{
    // Identify the original test run.

    // Create or retrieve existing SDA TestRunID.

    // Aggregate singular tables.

    // Aggregate relational tables.

    // Commit changes.
}
```

The key behavior:

| Scenario                      | Expected behavior                             |
| ----------------------------- | --------------------------------------------- |
| New database                  | Create test run and aggregate all data        |
| Previously processed database | Update existing records                       |
| Newly added table             | Insert missing records                        |
| Newly added field             | Update existing records                       |
| Same database processed again | No duplicate records                          |
| Changed HIC mapping           | Update mapping for the corresponding test run |

I would also use a database transaction where practical so a failed reprocessing operation does not leave the SDA partially updated.

For the future background agent, consider keeping a processing history with the source database identifier, last processing time, status, and error details.

## 5. A few things I would correct in your existing design

There are some additional technical issues worth addressing.

A. Primary keys need to be explicit

For every singular table, distinguish:

- Source primary key.
- Destination primary key.
- Foreign key to the SDA `TestRun`.
- Columns used to identify a record during upsert.

For example, HIC might use `(TestRunID, HICCode)`, while CSC might need `(TestRunID, CSCId)` or a different composite key depending on the actual schema.

B. Don't make all column names configurable unnecessarily

Your lead specifically mentioned reducing unnecessary abstractions.

Make source/destination table names, key columns, and column mappings configurable when they genuinely vary.

Do not create configuration settings for fixed internal concepts that will never change.

C. CSC should preserve detailed information

Don't aggregate only the representative HIC code and discard the individual CSC records.

Preserve detailed CSC information and provide a simpler view or query for BIT consumers. That way SW can access the complete dataset without forcing every consumer to retrieve it.

D. Be careful with SQL generation

Your current configuration contains expressions such as:

```
joinCondition="tr.TestRunID=s.TestRunID"
```

If you retain configurable SQL expressions, validate table names, aliases, columns, and join types against the configuration schema. SQL parameters cannot parameterize table or column identifiers.

Also, your current root-table configuration references alias `tr`, but doesn't explicitly define the test-run source table alias. That should be made consistent.

E. Register custom configuration sections

Your current XML uses custom elements such as `<CommonHeaders>`, `<TestRunTables>`, and `<RootTables>`. Standard .NET configuration does not automatically understand arbitrary elements. Make sure the corresponding custom section handlers are registered under `<configSections>` or use an appropriate configuration provider.

## 6. Recommended implementation sequence

I would approach this in stages rather than refactoring everything simultaneously.

1. Understand existing implementation

   Identify the existing configuration reader, `TestRunProperty` parser, relational aggregator, and SDA insertion logic.
2. Introduce generic configuration models

   Implement `TableDefinition`, `ColumnMapping`, and `TestRunIdentity`.
3. Implement generic singular-table aggregation

   Move `TestRunProperty` into the generic mechanism first and verify existing behavior.
4. Add additional data

   Add SUT SN, HIC mapping, and CSC model/version aggregation.
5. Implement historical reprocessing

   Introduce reliable test-run identification and upsert behavior.
6. Regression and performance testing

   Compare old and new aggregation results and test with databases containing large numbers of CSC records.

## 7. What I would clarify with your lead before implementation

There are three particularly important questions:

1. Should `TestRunProperty` remain the authoritative source for identifying a test run, or can another source table provide that identity?
2. Should the generic singular-table mechanism support tables whose source primary keys differ from their SDA destination keys?
3. For historical reprocessing, should the aggregator reprocess all tables every time, or support selectively updating newly introduced tables and fields?

My recommendation is to support both full and selective reprocessing, even if the first implementation only needs full reprocessing.

My overall recommendation: Don't simply rename `TestRunTables` to `SingularTables`. Change the C# architecture so that aggregation behavior is driven by generic table definitions, while test-run identification and relational message processing remain separate responsibilities.

That is much closer to what your lead is asking for: a scalable aggregation engine rather than an application that needs new special-case code every time another table is introduced.

The next useful step would be to review your existing C# configuration reader and aggregation methods against this proposed design, so we can identify exactly which classes and methods need modification rather than rewriting working code unnecessarily.



==================================ACTUAL IMPLEMENTATION ======================================

Understood. I'll give you a complete reference implementation based on the `app.config` you provided, without requiring your existing project files.

I'll use the following assumptions:

- C# application using .NET Framework 4.8.
- SQLite is the source database.
- Microsoft SQL Server is the destination SDA database.
- `System.Data.SQLite` is used for SQLite access.
- `System.Data.SqlClient` is used for SQL Server access.
- The destination SDA database has a `TestRun` table with a unique source-test-run identifier.
- `TestRunProperty`, HIC, CSC, and other standalone tables use the generic aggregation mechanism.
- Root/child aggregation remains a separate mechanism.

This implementation will support:

1. Generic singular-table configuration.
2. Source-to-destination column mapping.
3. Primary-key-based upserts.
4. Test-run identification and duplicate prevention.
5. SUT SN aggregation.
6. Test-run-specific HIC mappings.
7. Test-run-specific CSC model/version records.
8. Historical reprocessing.
9. Existing root/child relationship configuration.

One important qualification: the source table and column names for HIC, CSC, and SUT SN in your example are illustrative. You must replace them with the actual names in your SQLite database. The relational implementation below uses a generic per-table reader and parent-key mapping rather than reproducing every possible join behavior in your current application.

# 1. Project structure

Create the following files:

```
DataAggregator/
│
├── App.config
├── Program.cs
├── Configuration/
│   ├── AggregatorConfiguration.cs
│   └── ConfigurationLoader.cs
│
├── Models/
│   ├── TableDefinition.cs
│   └── ColumnMapping.cs
│
├── Data/
│   ├── SQLiteDataReader.cs
│   └── SqlServerDataWriter.cs
│
├── Services/
│   ├── TestRunService.cs
│   ├── SingularTableAggregator.cs
│   ├── RelationalTableAggregator.cs
│   └── DataAggregator.cs
│
└── Utilities/
    └── SqlIdentifier.cs
```

# 2. App.config

This is the redesigned configuration. Notice that `TestRunProperty` is now just another entry under `SingularTables`.

```

<?xml version="1.0" encoding="utf-8"?>

<configuration>

  <appSettings>
    <add key="AnalysisServer" value="MSSQLServerName" />
    <add key="AnalysisDatabaseName" value="MSSQLDatabaseName" />
  </appSettings>

  <configSections>
    <section name="DataAggregator"
             type="DataAggregator.Configuration.AggregatorConfiguration, DataAggregator" />
  </configSections>

  <DataAggregator>

    <CommonHeaders
        value="SourceSystem,ImportedBy,ImportDate"
        headerValues="SQLite,DataTransferApp,{UTCNOW}" />

    <TestRunIdentity
        sourceTable="TestRunProperty"
        sourceKey="TestRunID"
        destinationTable="TestRun"
        destinationKey="TestRunID"
        sourceDatabaseKey="SourceDatabase" />

    <SingularTables>

      <Table name="TestRunProperty"
             sourceTable="TestRunProperty"
             destinationTable="TestRunProperty"
             sourceKey="TestRunID"
             destinationKey="TestRunID">

        <Columns>
          <Column source="TestDate" destination="TestDate" />
          <Column source="TestLine" destination="TestLine" />
          <Column source="SUTSN" destination="SUTSN" />
        </Columns>

      </Table>

      <Table name="HICLookup"
             sourceTable="HICLookup"
             destinationTable="TestRunHICLookup"
             sourceKey="HICCode"
             destinationKey="HICCode">

        <Columns>
          <Column source="HICCode" destination="HICCode" />
          <Column source="Description" destination="Description" />
        </Columns>

      </Table>

      <Table name="CSC"
             sourceTable="CSC"
             destinationTable="TestRunCSC"
             sourceKey="CSCId"
             destinationKey="CSCId">

        <Columns>
          <Column source="CSCId" destination="CSCId" />
          <Column source="Model" destination="Model" />
          <Column source="Version" destination="Version" />
        </Columns>

      </Table>

    </SingularTables>

    <RelationalTables>

      <RootTables>

        <Table name="Student"
               sourceTable="Student"
               destinationTable="StudentReport"
               parentKey="TestRunID"
               sourceKey="StudentID">

          <Columns>
            <Column source="StudentID" destination="StudentID" />
            <Column source="FirstName" destination="FirstName" />
            <Column source="LastName" destination="LastName" />
          </Columns>

        </Table>

        <Table name="Teacher"
               sourceTable="Teacher"
               destinationTable="TeacherReport"
               parentKey="TestRunID"
               sourceKey="TeacherID">

          <Columns>
            <Column source="TeacherID" destination="TeacherID" />
            <Column source="Name" destination="Name" />
            <Column source="Email" destination="Email" />
          </Columns>

        </Table>

      </RootTables>

      <ChildTables>

        <Table name="StudentDetails"
               sourceTable="StudentDetails"
               destinationTable="StudentDetails"
               parent="Student"
               parentKey="StudentID"
               sourceKey="StudentID">

          <Columns>
            <Column source="Email" destination="Email" />
            <Column source="Phone" destination="Phone" />
            <Column source="Address" destination="Address" />
          </Columns>

        </Table>

        <Table name="CompetitionResults"
               sourceTable="CompetitionResults"
               destinationTable="CompetitionResults"
               parent="Student"
               parentKey="StudentID"
               sourceKey="StudentID">

          <Columns>
            <Column source="CompetitionID" destination="CompetitionID" />
            <Column source="Score" destination="Score" />
            <Column source="Rank" destination="Rank" />
          </Columns>

        </Table>

      </ChildTables>

    </RelationalTables>

  </DataAggregator>

  <startup>
    <supportedRuntime version="v4.0"
                      sku=".NETFramework,Version=v4.8" />
  </startup>

</configuration>

```

A few deliberate differences from your original configuration:

- No numbered `TestRunTable1`, `TestRunTable2`.
- No `TestRunPropertyTableName` or similar settings.
- All singular tables use the same definition.
- `TestRunIdentity` identifies the source test run separately.
- Source and destination columns are mapped individually.
- Parent/child relationships remain distinct.

The `sourceDatabaseKey` should be used to identify the source database in the SDA, not assumed to be a built-in SQL Server field.

# 3. Configuration models

Create `Models/ColumnMapping.cs`:

```

namespace DataAggregator.Models
{
    public class ColumnMapping
    {
        public string Source { get; set; }
        public string Destination { get; set; }
    }
}

```

Create `Models/TableDefinition.cs`:

```

using System.Collections.Generic;

namespace DataAggregator.Models
{
    public class TableDefinition
    {
        public string Name { get; set; }
        public string SourceTable { get; set; }
        public string DestinationTable { get; set; }
        public string Parent { get; set; }
        public string ParentKey { get; set; }

        public List<string> KeyColumns { get; set; }
            = new List<string>();

        public List<ColumnMapping> Columns { get; set; }
            = new List<ColumnMapping>();
    }
}

```

Create `Configuration/AggregatorConfiguration.cs`:

```

using System.Collections.Generic;
using DataAggregator.Models;

namespace DataAggregator.Configuration
{
    public class AggregatorConfiguration
    {
        public string AnalysisServer { get; set; }
        public string AnalysisDatabaseName { get; set; }

        public string TestRunSourceTable { get; set; }
        public string TestRunSourceKey { get; set; }
        public string TestRunDestinationTable { get; set; }
        public string TestRunDestinationKey { get; set; }

        public string[] HeaderNames { get; set; }
        public string[] HeaderValues { get; set; }

        public List<TableDefinition> SingularTables { get; set; }
            = new List<TableDefinition>();

        public List<TableDefinition> RootTables { get; set; }
            = new List<TableDefinition>();

        public List<TableDefinition> ChildTables { get; set; }
            = new List<TableDefinition>();
    }
}

```

# 4. Configuration loader

For this implementation, I recommend using `XDocument` to read the custom configuration rather than creating multiple custom .NET configuration section handlers.

This keeps the configuration loader relatively simple.

Also, it avoids the need to register a custom section handler in `configSections`.

The XML should therefore have this order:

```
<configuration>
  <appSettings>
    ...
  </appSettings>

  <DataAggregator>
    ...
  </DataAggregator>

  <startup>
    ...
  </startup>
</configuration>
```

Create `Configuration/ConfigurationLoader.cs`:

```

using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Xml.Linq;
using DataAggregator.Models;

namespace DataAggregator.Configuration
{
    public static class ConfigurationLoader
    {
        public static AggregatorConfiguration Load()
        {
            var configPath =
                AppDomain.CurrentDomain.SetupInformation.ConfigurationFile;

            var document = XDocument.Load(configPath);

            var root = document.Root?
                .Element("DataAggregator");

            if (root == null)
                throw new ConfigurationErrorsException(
                    "DataAggregator configuration is missing.");

            var config = new AggregatorConfiguration
            {
                AnalysisServer =
                    ConfigurationManager.AppSettings["AnalysisServer"],

                AnalysisDatabaseName =
                    ConfigurationManager.AppSettings["AnalysisDatabaseName"]
            };

            var headers = root.Element("CommonHeaders");

            if (headers != null)
            {
                config.HeaderNames = Split(
                    (string)headers.Attribute("value"));

                config.HeaderValues = Split(
                    (string)headers.Attribute("headerValues"));

                if (config.HeaderNames.Length != config.HeaderValues.Length)
                    throw new ConfigurationErrorsException(
                        "CommonHeaders names and values must have matching lengths.");
            }

            var identity = root.Element("TestRunIdentity");

            if (identity == null)
                throw new ConfigurationErrorsException(
                    "TestRunIdentity configuration is missing.");

            config.TestRunSourceTable =
                Required(identity, "sourceTable");

            config.TestRunSourceKey =
                Required(identity, "sourceKey");

            config.TestRunDestinationTable =
                Required(identity, "destinationTable");

            config.TestRunDestinationKey =
                Required(identity, "destinationKey");

            config.SingularTables = LoadTables(
                root.Element("SingularTables"));

            var relational = root.Element("RelationalTables");

            config.RootTables = LoadTables(
                relational?.Element("RootTables"));

            config.ChildTables = LoadTables(
                relational?.Element("ChildTables"));

            return config;
        }

        private static List<TableDefinition> LoadTables(
            XElement section)
        {
            var result = new List<TableDefinition>();

            if (section == null)
                return result;

            foreach (var element in section.Elements("Table"))
            {
                var table = new TableDefinition
                {
                    Name = Required(element, "name"),
                    SourceTable = Required(element, "sourceTable"),
                    DestinationTable = Required(
                        element, "destinationTable"),

                    Parent = (string)element.Attribute("parent"),
                    ParentKey = (string)element.Attribute("parentKey"),

                    KeyColumns = Split(
                        (string)element.Attribute("keyColumns"))
                };

                if (table.KeyColumns.Count == 0)
                {
                    // Support the original root/child configuration.
                    var key = (string)element.Attribute("sourceKey");

                    if (!string.IsNullOrWhiteSpace(key))
                        table.KeyColumns.Add(key);
                }

                var columns = element.Element("Columns");

                if (columns != null)
                {
                    foreach (var column in columns.Elements("Column"))
                    {
                        table.Columns.Add(new ColumnMapping
                        {
                            Source = Required(column, "source"),
                            Destination = Required(
                                column, "destination")
                        });
                    }
                }

                if (table.Columns.Count == 0)
                    throw new ConfigurationErrorsException(
                        $"No columns configured for {table.Name}.");

                if (table.KeyColumns.Count == 0)
                    throw new ConfigurationErrorsException(
                        $"No key columns configured for {table.Name}.");

                result.Add(table);
            }

            return result;
        }

        private static string Required(
            XElement element,
            string attribute)
        {
            var value = (string)element.Attribute(attribute);

            if (string.IsNullOrWhiteSpace(value))
                throw new ConfigurationErrorsException(
                    $"Missing attribute '{attribute}' in {element.Name}.");

            return value.Trim();
        }

        private static string[] Split(string value)
        {
            return string.IsNullOrWhiteSpace(value)
                ? Array.Empty<string>()
                : value.Split(',')
                    .Select(x => x.Trim())
                    .Where(x => x.Length > 0)
                    .ToArray();
        }
    }
}

```

Notice that `KeyColumns` is now generic. There is no `TestRunPropertyPrimaryKey` property in the configuration model.

# 5. SQL identifier utility

Because table and column names cannot be passed as ordinary SQL parameters, validate and quote identifiers.

Create `Utilities/SqlIdentifier.cs`:

```

using System;
using System.Text.RegularExpressions;

namespace DataAggregator.Utilities
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
                    "Invalid SQL identifier: " + identifier);
            }

            return "[" + identifier + "]";
        }

        public static string QuoteQualified(string identifier)
        {
            var parts = identifier.Split('.');

            return string.Join(".",
                Array.ConvertAll(parts, Quote));
        }
    }
}

```

This intentionally supports simple schema-qualified identifiers such as `dbo.TestRun`. If your existing configuration uses more complex SQL expressions or quoted identifiers, those need separate validation.

# 6. SQLite source reader

Create `Data/SQLiteSourceReader.cs`:

```

using System;
using System.Collections.Generic;
using System.Data;
using System.Data.SQLite;
using System.Linq;
using DataAggregator.Models;
using DataAggregator.Utilities;

namespace DataAggregator.Data
{
    public class SQLiteSourceReader
    {
        private readonly SQLiteConnection connection;

        public SQLiteSourceReader(SQLiteConnection connection)
        {
            this.connection = connection;
        }

        public object GetSingleValue(
            string table,
            string column)
        {
            string sql =
                $"SELECT {SqlIdentifier.Quote(column)} " +
                $"FROM {SqlIdentifier.Quote(table)} LIMIT 1";

            using (var command = new SQLiteCommand(sql, connection))
            {
                return command.ExecuteScalar();
            }
        }

        public List<Dictionary<string, object>> ReadTable(
            TableDefinition table)
        {
            var columns = table.Columns
                .Select(x => x.Source)
                .Concat(table.KeyColumns)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();

            string sql =
                "SELECT " +
                string.Join(", ", columns.Select(SqlIdentifier.Quote)) +
                " FROM " + SqlIdentifier.Quote(table.SourceTable);

            using (var command = new SQLiteCommand(sql, connection))
            using (var reader = command.ExecuteReader())
            {
                var results =
                    new List<Dictionary<string, object>>();

                while (reader.Read())
                {
                    var record =
                        new Dictionary<string, object>(
                            StringComparer.OrdinalIgnoreCase);

                    for (int i = 0; i < reader.FieldCount; i++)
                    {
                        record[reader.GetName(i)] =
                            reader.IsDBNull(i)
                                ? DBNull.Value
                                : reader.GetValue(i);
                    }

                    results.Add(record);
                }

                return results;
            }
        }

        public List<Dictionary<string, object>> ReadTable(
            TableDefinition table,
            string filterColumn,
            object filterValue)
        {
            var columns = table.Columns
                .Select(x => x.Source)
                .Concat(table.KeyColumns)
                .Append(filterColumn)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();

            string sql =
                "SELECT " +
                string.Join(", ", columns.Select(SqlIdentifier.Quote)) +
                " FROM " + SqlIdentifier.Quote(table.SourceTable) +
                " WHERE " + SqlIdentifier.Quote(filterColumn) +
                " = @filter";

            using (var command = new SQLiteCommand(sql, connection))
            {
                command.Parameters.AddWithValue(
                    "@filter", filterValue ?? DBNull.Value);

                using (var reader = command.ExecuteReader())
                {
                    var results =
                        new List<Dictionary<string, object>>();

                    while (reader.Read())
                    {
                        var record =
                            new Dictionary<string, object>(
                                StringComparer.OrdinalIgnoreCase);

                        for (int i = 0; i < reader.FieldCount; i++)
                        {
                            record[reader.GetName(i)] =
                                reader.IsDBNull(i)
                                    ? DBNull.Value
                                    : reader.GetValue(i);
                        }

                        results.Add(record);
                    }

                    return results;
                }
            }
        }
    }
}

```

This reader assumes the configured source table and columns exist. A production implementation should validate those names against `sqlite_master` and `PRAGMA table_info` before processing.

# 7. SQL Server destination writer

Create `Data/SqlServerDataWriter.cs`.

This class handles inserts and updates using the configured key columns. It also applies common headers.

```

using System;
using System.Collections.Generic;
using System.Data;
using System.Data.SqlClient;
using System.Linq;
using DataAggregator.Utilities;

namespace DataAggregator.Data
{
    public class SqlServerDataWriter
    {
        private readonly SqlConnection connection;
        private readonly SqlTransaction transaction;

        public SqlServerDataWriter(
            SqlConnection connection,
            SqlTransaction transaction)
        {
            this.connection = connection;
            this.transaction = transaction;
        }

        public void Upsert(
            string table,
            Dictionary<string, object> record,
            IEnumerable<string> keyColumns)
        {
            var keys = keyColumns.ToList();

            if (keys.Count == 0)
                throw new InvalidOperationException(
                    "Upsert requires at least one key column.");

            foreach (var key in keys)
            {
                if (!record.ContainsKey(key))
                    throw new InvalidOperationException(
                        $"Key column '{key}' is missing from {table}.");
            }

            var columns = record.Keys.ToList();

            string match = string.Join(" AND ",
                keys.Select(k =>
                    $"target.{SqlIdentifier.Quote(k)} = " +
                    $"source.{SqlIdentifier.Quote(k)}"));

            var nonKeys = columns
                .Where(c => !keys.Contains(
                    c, StringComparer.OrdinalIgnoreCase))
                .ToList();

            string update = nonKeys.Count == 0
                ? ""
                : "WHEN MATCHED THEN UPDATE SET " +
                  string.Join(", ",
                      nonKeys.Select(c =>
                          $"target.{SqlIdentifier.Quote(c)} = " +
                          $"source.{SqlIdentifier.Quote(c)}"));

            string insertColumns = string.Join(", ",
                columns.Select(SqlIdentifier.Quote));

            string insertValues = string.Join(", ",
                columns.Select(c =>
                    $"source.{SqlIdentifier.Quote(c)}"));

            string sourceValues = string.Join(", ",
                columns.Select((c, i) => $"@p{i} AS {SqlIdentifier.Quote(c)}"));

            string sql = $@"
MERGE INTO {SqlIdentifier.QuoteQualified(table)} AS target
USING (SELECT {sourceValues}) AS source
ON {match}
{update}
WHEN NOT MATCHED THEN
    INSERT ({insertColumns})
    VALUES ({insertValues});";

            using (var command = new SqlCommand(
                sql, connection, transaction))
            {
                for (int i = 0; i < columns.Count; i++)
                {
                    command.Parameters.AddWithValue(
                        $"@p{i}",
                        record[columns[i]] ?? DBNull.Value);
                }

                command.ExecuteNonQuery();
            }
        }
    }
}

```

The `MERGE` statement provides the basic insert/update behavior. In production, also enforce unique constraints on the destination keys and handle concurrent ingestion safely. SQL Server's `MERGE` has concurrency and implementation caveats, so for a high-volume or concurrent system I would consider a transactionally protected `UPDATE` followed by `INSERT` when no row was updated.

# 8. Test-run identification

This is one of the most important components.

The aggregator must distinguish the source test-run identifier from the SDA's destination test-run identifier.

For example:

| Source database | Source TestRunID | SDA TestRunID |
| --------------- | ---------------- | ------------- |
| run001.db       | 100              | 5001          |
| run002.db       | 100              | 5002          |
| run003.db       | 101              | 5003          |

The same source ID can occur in different SQLite databases. Therefore, using only the source `TestRunID` as the SDA identity is unsafe.

Create `Services/TestRunService.cs`:

```

using System;
using System.Data.SqlClient;
using System.Data.SQLite;
using DataAggregator.Configuration;
using DataAggregator.Data;
using DataAggregator.Utilities;

namespace DataAggregator.Services
{
    public class TestRunService
    {
        private readonly AggregatorConfiguration config;

        public TestRunService(AggregatorConfiguration config)
        {
            this.config = config;
        }

        public long GetOrCreate(
            SQLiteConnection source,
            SqlConnection destination,
            SqlTransaction transaction,
            string sourceDatabase)
        {
            var reader = new SQLiteSourceReader(source);

            object sourceId = reader.GetSingleValue(
                config.TestRunSourceTable,
                config.TestRunSourceKey);

            if (sourceId == null || sourceId == DBNull.Value)
                throw new InvalidOperationException(
                    "Source TestRunID was not found.");

            const string sourceDatabaseColumn = "SourceDatabase";
            const string sourceIdColumn = "SourceTestRunID";

            string table = SqlIdentifier.QuoteQualified(
                config.TestRunDestinationTable);

            string destinationKey = SqlIdentifier.Quote(
                config.TestRunDestinationKey);

            string sql = $@"
SELECT {destinationKey}
FROM {table} WITH (UPDLOCK, HOLDLOCK)
WHERE [SourceDatabase] = @database
  AND [SourceTestRunID] = @sourceId;";

            using (var command = new SqlCommand(
                sql, destination, transaction))
            {
                command.Parameters.AddWithValue(
                    "@database", sourceDatabase);

                command.Parameters.AddWithValue(
                    "@sourceId", sourceId);

                object existing = command.ExecuteScalar();

                if (existing != null && existing != DBNull.Value)
                    return Convert.ToInt64(existing);
            }

            string insert = $@"
INSERT INTO {table}
(
    [SourceDatabase],
    [SourceTestRunID]
)
OUTPUT INSERTED.{destinationKey}
VALUES
(
    @database,
    @sourceId
);";

            using (var command = new SqlCommand(
                insert, destination, transaction))
            {
                command.Parameters.AddWithValue(
                    "@database", sourceDatabase);

                command.Parameters.AddWithValue(
                    "@sourceId", sourceId);

                return Convert.ToInt64(
                    command.ExecuteScalar());
            }
        }
    }
}

```

This example assumes that the SDA `TestRun` table has `SourceDatabase` and `SourceTestRunID` columns. Those are illustrative integration columns; if your existing SDA schema already has a source-database identifier or another stable unique key, use that instead.

Also, use a unique database constraint on `(SourceDatabase, SourceTestRunID)` to prevent concurrent duplicate creation.

# 9. Generic singular-table aggregator

This is the main refactoring requested by your lead.

Create `Services/SingularTableAggregator.cs`:

```

using System;
using System.Collections.Generic;
using System.Data;
using System.Data.SqlClient;
using System.Data.SQLite;
using System.Linq;
using DataAggregator.Configuration;
using DataAggregator.Data;
using DataAggregator.Models;

namespace DataAggregator.Services
{
    public class SingularTableAggregator
    {
        private readonly AggregatorConfiguration config;

        public SingularTableAggregator(
            AggregatorConfiguration config)
        {
            this.config = config;
        }

        public void Aggregate(
            SQLiteConnection source,
            SqlConnection destination,
            SqlTransaction transaction,
            long testRunId)
        {
            var reader = new SQLiteSourceReader(source);

            var writer = new SqlServerDataWriter(
                destination, transaction);

            foreach (var table in config.SingularTables)
            {
                AggregateTable(
                    reader,
                    writer,
                    table,
                    testRunId);
            }
        }

        private void AggregateTable(
            SQLiteSourceReader reader,
            SqlServerDataWriter writer,
            TableDefinition table,
            long testRunId)
        {
            var records = reader.ReadTable(table);

            foreach (var sourceRecord in records)
            {
                var destinationRecord =
                    new Dictionary<string, object>(
                        StringComparer.OrdinalIgnoreCase);

                foreach (var mapping in table.Columns)
                {
                    if (!sourceRecord.TryGetValue(
                        mapping.Source, out var value))
                    {
                        throw new InvalidOperationException(
                            $"Source column '{mapping.Source}' " +
                            $"not found in {table.SourceTable}.");
                    }

                    destinationRecord[mapping.Destination] = value;
                }

                // The SDA TestRunID is assigned by TestRunService.
                // It must not be copied blindly from SQLite.

                destinationRecord["TestRunID"] = testRunId;

                ApplyCommonHeaders(destinationRecord);

                var keys = new List<string>
                {
                    "TestRunID"
                };

                keys.AddRange(
                    table.KeyColumns.Where(k =>
                        !k.Equals("TestRunID",
                            StringComparison.OrdinalIgnoreCase)));

                writer.Upsert(
                    table.DestinationTable,
                    destinationRecord,
                    keys);
            }
        }

        private void ApplyCommonHeaders(
            Dictionary<string, object> record)
        {
            if (config.HeaderNames == null)
                return;

            for (int i = 0; i < config.HeaderNames.Length; i++)
            {
                string value = config.HeaderValues[i];

                if (value == "{UTCNOW}")
                    record[config.HeaderNames[i]] = DateTime.UtcNow;
                else
                    record[config.HeaderNames[i]] = value;
            }
        }
    }
}

```

Now consider the advantage.

Before:

```
if (tableName == "TestRunProperty")
{
    // Handle TestRunProperty
}
```

After:

```
foreach (var table in config.SingularTables)
{
    AggregateTable(table);
}
```

Adding a new standalone table becomes primarily a configuration change.

Important correction for your actual schema: This implementation injects `TestRunID` into every singular destination record. That assumes all these destination tables have a `TestRunID` column. It also assumes the configured `KeyColumns` identify source records and that `TestRunID` is the destination run foreign key. Validate those assumptions before using it.

# 10. Root and child relational aggregator

Your lead did not ask you to replace the existing parent/child aggregation mechanism. I would preserve it and make it independent of the singular-table aggregator.

The following implementation uses the parent relationship in configuration to determine processing order and filter child records.

Create `Services/RelationalTableAggregator.cs`:

```

using System;
using System.Collections.Generic;
using System.Data.SqlClient;
using System.Data.SQLite;
using System.Linq;
using DataAggregator.Configuration;
using DataAggregator.Data;
using DataAggregator.Models;

namespace DataAggregator.Services
{
    public class RelationalTableAggregator
    {
        private readonly AggregatorConfiguration config;

        public RelationalTableAggregator(
            AggregatorConfiguration config)
        {
            this.config = config;
        }

        public void Aggregate(
            SQLiteConnection source,
            SqlConnection destination,
            SqlTransaction transaction,
            object sourceTestRunId,
            long destinationTestRunId)
        {
            var reader = new SQLiteSourceReader(source);

            var writer = new SqlServerDataWriter(
                destination, transaction);

            var allTables = config.RootTables
                .Concat(config.ChildTables)
                .ToList();

            var processed = new Dictionary<
                string,
                List<Dictionary<string, object>>>(
                    StringComparer.OrdinalIgnoreCase);

            foreach (var table in allTables)
            {
                List<Dictionary<string, object>> records;

                if (string.IsNullOrWhiteSpace(table.Parent))
                {
                    // Root table: filter by source TestRunID.
                    records = reader.ReadTable(
                        table,
                        table.ParentKey,
                        sourceTestRunId);
                }
                else
                {
                    // Child table: find the parent records.
                    if (!processed.TryGetValue(
                        table.Parent, out var parentRecords))
                    {
                        throw new InvalidOperationException(
                            $"Parent '{table.Parent}' must be " +
                            "processed before child '" + table.Name + "'.");
                    }

                    var parentIds = parentRecords
                        .Where(x => x.ContainsKey(table.ParentKey))
                        .Select(x => x[table.ParentKey])
                        .Where(x => x != null && x != DBNull.Value)
                        .Distinct()
                        .ToList();

                    records = new List<Dictionary<string, object>>();

                    foreach (var parentId in parentIds)
                    {
                        records.AddRange(reader.ReadTable(
                            table,
                            table.ParentKey,
                            parentId));
                    }
                }

                foreach (var sourceRecord in records)
                {
                    var destinationRecord =
                        new Dictionary<string, object>(
                            StringComparer.OrdinalIgnoreCase);

                    foreach (var mapping in table.Columns)
                    {
                        if (!sourceRecord.TryGetValue(
                            mapping.Source, out var value))
                        {
                            throw new InvalidOperationException(
                                $"Missing source column " +
                                $"{mapping.Source} in {table.SourceTable}.");
                        }

                        destinationRecord[mapping.Destination] = value;
                    }

                    destinationRecord["TestRunID"] =
                        destinationTestRunId;

                    ApplyCommonHeaders(destinationRecord);

                    var keys = new List<string>
                    {
                        "TestRunID"
                    };

                    keys.AddRange(table.KeyColumns.Where(k =>
                        !k.Equals("TestRunID",
                            StringComparison.OrdinalIgnoreCase)));

                    writer.Upsert(
                        table.DestinationTable,
                        destinationRecord,
                        keys);
                }

                processed[table.Name] = records;
            }
        }

        private void ApplyCommonHeaders(
            Dictionary<string, object> record)
        {
            if (config.HeaderNames == null)
                return;

            for (int i = 0; i < config.HeaderNames.Length; i++)
            {
                string value = config.HeaderValues[i];

                record[config.HeaderNames[i]] =
                    value == "{UTCNOW}"
                        ? (object)DateTime.UtcNow
                        : value;
            }
        }
    }
}

```

A few details are important:

- The root table is filtered using the source test-run ID.
- Child tables are filtered using their parent's key values.
- The destination receives the SDA test-run ID.
- Each table uses its own configured key columns.

This is a basic generic parent/child implementation, not a replacement for a more sophisticated existing join engine. For example, if a child depends on a composite parent key, or the destination uses different foreign-key identifiers, the mapping needs to be extended.

Also, for larger databases, replace the per-parent query with a batched `IN` query or streaming join to avoid an excessive number of SQLite queries.

# 11. Main DataAggregator service

Now bring everything together.

Create `Services/DataAggregator.cs`:

```

using System;
using System.Data.SqlClient;
using System.Data.SQLite;
using System.IO;
using DataAggregator.Configuration;

namespace DataAggregator.Services
{
    public class DataAggregator
    {
        private readonly AggregatorConfiguration config;

        public DataAggregator(
            AggregatorConfiguration config)
        {
            this.config = config;
        }

        public void AggregateDatabase(string sourceDatabase)
        {
            if (!File.Exists(sourceDatabase))
                throw new FileNotFoundException(
                    "Source SQLite database not found.",
                    sourceDatabase);

            string sourcePath =
                Path.GetFullPath(sourceDatabase);

            string sqliteConnectionString =
                $"Data Source={sourcePath};Version=3;";

            string sqlConnectionString =
                new SqlConnectionStringBuilder
                {
                    DataSource = config.AnalysisServer,
                    InitialCatalog = config.AnalysisDatabaseName,
                    IntegratedSecurity = true,
                    TrustServerCertificate = true
                }.ConnectionString;

            using (var source = new SQLiteConnection(
                sqliteConnectionString))
            using (var destination = new SqlConnection(
                sqlConnectionString))
            {
                source.Open();
                destination.Open();

                using (var transaction =
                    destination.BeginTransaction())
                {
                    try
                    {
                        var testRunService =
                            new TestRunService(config);

                        long testRunId =
                            testRunService.GetOrCreate(
                                source,
                                destination,
                                transaction,
                                sourcePath);

                        var singularAggregator =
                            new SingularTableAggregator(config);

                        singularAggregator.Aggregate(
                            source,
                            destination,
                            transaction,
                            testRunId);

                        var relationalAggregator =
                            new RelationalTableAggregator(config);

                        object sourceTestRunId =
                            new Data.SQLiteSourceReader(source)
                                .GetSingleValue(
                                    config.TestRunSourceTable,
                                    config.TestRunSourceKey);

                        relationalAggregator.Aggregate(
                            source,
                            destination,
                            transaction,
                            sourceTestRunId,
                            testRunId);

                        transaction.Commit();

                        Console.WriteLine(
                            $"Aggregation completed. SDA TestRunID: {testRunId}");
                    }
                    catch
                    {
                        transaction.Rollback();
                        throw;
                    }
                }
            }
        }
    }
}

```

There is one namespace detail to correct in this file: the reader class is declared in `DataAggregator.Data`, so add:

```
using DataAggregator.Data;
```

Then use:

```
new SQLiteSourceReader(source)
```

instead of `new Data.SQLiteSourceReader(source)`.

# 12. Program.cs

This is the entry point.

It supports passing a source SQLite database path from the command line.

Create `Program.cs`:

```

using System;
using DataAggregator.Configuration;
using DataAggregator.Services;

namespace DataAggregator
{
    internal class Program
    {
        static int Main(string[] args)
        {
            try
            {
                if (args.Length < 1)
                {
                    Console.WriteLine(
                        "Usage: DataAggregator.exe <source.db>");

                    return 1;
                }

                var config = ConfigurationLoader.Load();

                var aggregator = new DataAggregator.Services.DataAggregator(
                    config);

                aggregator.AggregateDatabase(args[0]);

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

Example:

```
DataAggregator.exe "C:\TestResults\Run1001.db"
```

You can now invoke the same executable from:

- The normal test-run workflow.
- A manually initiated historical reprocessing operation.
- A future scheduled background agent.

All three use the same aggregation engine.

# 13. Example SDA database schema

The code above needs a destination schema that supports the configured records.

Here is an example SQL Server schema. This is a reference schema; adapt it to your actual SDA tables rather than executing it blindly against an existing database.

```
CREATE TABLE dbo.TestRun
(
    TestRunID BIGINT IDENTITY(1,1) PRIMARY KEY,
    SourceDatabase NVARCHAR(500) NOT NULL,
    SourceTestRunID NVARCHAR(100) NOT NULL,

    CONSTRAINT UQ_TestRun_Source
        UNIQUE (SourceDatabase, SourceTestRunID)
);
```

Test-run properties:

```
CREATE TABLE dbo.TestRunProperty
(
    TestRunID BIGINT NOT NULL PRIMARY KEY,
    TestDate DATETIME2 NULL,
    TestLine NVARCHAR(100) NULL,
    SUTSN NVARCHAR(100) NULL,

    SourceSystem NVARCHAR(100) NULL,
    ImportedBy NVARCHAR(100) NULL,
    ImportDate DATETIME2 NULL,

    CONSTRAINT FK_TestRunProperty_TestRun
        FOREIGN KEY (TestRunID)
        REFERENCES dbo.TestRun(TestRunID)
);
```

HIC mapping:

```
CREATE TABLE dbo.TestRunHICLookup
(
    TestRunID BIGINT NOT NULL,
    HICCode NVARCHAR(100) NOT NULL,
    Description NVARCHAR(1000) NULL,

    SourceSystem NVARCHAR(100) NULL,
    ImportedBy NVARCHAR(100) NULL,
    ImportDate DATETIME2 NULL,

    CONSTRAINT PK_TestRunHICLookup
        PRIMARY KEY (TestRunID, HICCode),

    CONSTRAINT FK_TestRunHICLookup_TestRun
        FOREIGN KEY (TestRunID)
        REFERENCES dbo.TestRun(TestRunID)
);
```

CSC information:

```
CREATE TABLE dbo.TestRunCSC
(
    TestRunID BIGINT NOT NULL,
    CSCId NVARCHAR(100) NOT NULL,
    Model NVARCHAR(200) NULL,
    Version NVARCHAR(100) NULL,

    SourceSystem NVARCHAR(100) NULL,
    ImportedBy NVARCHAR(100) NULL,
    ImportDate DATETIME2 NULL,

    CONSTRAINT PK_TestRunCSC
        PRIMARY KEY (TestRunID, CSCId),

    CONSTRAINT FK_TestRunCSC_TestRun
        FOREIGN KEY (TestRunID)
        REFERENCES dbo.TestRun(TestRunID)
);
```

For CSC filtering, add indexes if query patterns justify them:

```
CREATE INDEX IX_TestRunCSC_CSCId
ON dbo.TestRunCSC(CSCId);

CREATE INDEX IX_TestRunCSC_ModelVersion
ON dbo.TestRunCSC(Model, Version);
```

The most important part is that HIC and CSC now have `TestRunID` as part of their primary key. This preserves the historical information for each test run.

# 14. Important improvements before production

There are several things I would strengthen before deploying this reference implementation.

### A. Map source keys to destination keys

The current examples use identical source and destination key names. If they differ, the aggregator must translate the configured source key through its column mapping.

For example, replace the key construction in `SingularTableAggregator` with:

```
var keys = new List<string> { "TestRunID" };

foreach (var sourceKey in table.KeyColumns)
{
    if (sourceKey.Equals(
        "TestRunID",
        StringComparison.OrdinalIgnoreCase))
        continue;

    var mapping = table.Columns.FirstOrDefault(
        x => x.Source.Equals(
            sourceKey,
            StringComparison.OrdinalIgnoreCase));

    if (mapping == null)
        throw new InvalidOperationException(
            $"No destination mapping for key {sourceKey}");

    keys.Add(mapping.Destination);
}
```

Apply the same approach to the relational aggregator.

### B. Improve historical processing

The current implementation automatically supports repeated processing:

```
First execution:
    Create TestRun
    Insert TestRunProperty
    Insert HIC
    Insert CSC

Second execution:
    Find existing TestRun
    Update TestRunProperty
    Update HIC
    Update CSC
```

When you add a new configured table, the next execution inserts its missing records.

You should also consider recording:

- Source database identifier.
- Processing start and completion times.
- Processing status.
- Last error.
- Aggregator version.

This will be useful for the background agent.

### C. CSC performance

I would not aggregate CSC information through repeated joins for every student or message.

Instead, read the CSC table independently, aggregate it once per test run, and let SW and BIT query the appropriate level of detail.

### D. Validate table definitions

Before aggregation, validate:

- Source tables exist.
- Configured source columns exist.
- Destination tables exist.
- Destination columns exist.
- Configured keys are unique where required.
- All destination key columns are non-null.

Otherwise, configuration errors may only appear halfway through processing.

# 15. NuGet dependencies and build

For a .NET Framework 4.8 project, install:

```
Install-Package System.Data.SQLite.Core
```

You also need references to:

```
System.Configuration
System.Data
System.Xml.Linq
System.Data.SQLite
System.Data.SqlClient
```

A few final corrections:

1. In `ConfigurationLoader.cs`, change:
   ```
   KeyColumns = Split(
       (string)element.Attribute("keyColumns"))
   ```
   to:
   ```
   KeyColumns = Split(
       (string)element.Attribute("keyColumns")).ToList()
   ```
2. Remove `configSections` entirely from the earlier configuration example. This implementation loads the `DataAggregator` XML directly using `XDocument`.
3. For `CompetitionResults`, configure its actual composite source key, for example:
   ```
   keyColumns="StudentID,CompetitionID"
   ```
   Do not use only `StudentID` if a student can have multiple competition results.
4. Ensure every destination table receiving common headers has `SourceSystem`, `ImportedBy`, and `ImportDate` columns.
5. The `TestRun` insertion code assumes its other required columns have defaults or allow nulls. Adapt it if your existing SDA schema requires additional values.

# 16. How this addresses your lead's requirements

| Lead's requirement                            | Implementation                         |
| --------------------------------------------- | -------------------------------------- |
| Remove TestRunProperty-specific configuration | Generic `TableDefinition`              |
| Add more standalone tables                    | `SingularTables`                       |
| Preserve primary keys                         | `KeyColumns`                           |
| Add SUT SN                                    | Column mapping                         |
| Capture HIC mappings per run                  | `TestRunHICLookup`                     |
| Capture CSC model/version                     | `TestRunCSC`                           |
| Reprocess historical databases                | `GetOrCreate` + `Upsert`               |
| Avoid duplicate test runs                     | Source database + source run identity  |
| Future background agent                       | Same `AggregateDatabase()` entry point |

Recommended architecture

My recommendation for your actual project: Implement the generic singular-table mechanism first using `TestRunProperty` only. Compare the output against your existing aggregator. Once that works, add HIC, CSC, and SUT SN.

The code above is a complete reference baseline for the illustrated schema, but it is not yet a verified drop-in replacement for your existing application. In particular, the actual SDA schema, existing relational join behavior, source keys, and destination constraints must be reconciled before production use.
