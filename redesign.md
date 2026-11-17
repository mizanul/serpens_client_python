


using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using Microsoft.Data.SqlClient;

namespace DataAggregator
{
    public class SqlServerDataImporter
    {
        private readonly string _connectionString;

        public SqlServerDataImporter(string connectionString)
        {
            _connectionString = connectionString;
        }

        public void ImportAll(
            AggregatorConfig config,
            DataSet sourceData,
            int? sharedTestRunId = null)
        {
            using (var connection =
                new SqlConnection(_connectionString))
            {
                connection.Open();

                using (var transaction =
                    connection.BeginTransaction())
                {
                    try
                    {
                        // Process parent tables before child tables.
                        var orderedTables =
                            config.GetTablesInDependencyOrder();

                        foreach (TableDefinition definition in orderedTables)
                        {
                            if (!sourceData.Tables.Contains(
                                definition.SourceTable))
                            {
                                throw new InvalidOperationException(
                                    $"Source table '{definition.SourceTable}' " +
                                    "does not exist in the DataSet.");
                            }

                            DataTable source =
                                sourceData.Tables[definition.SourceTable];

                            ImportTable(
                                connection,
                                transaction,
                                definition,
                                source,
                                sharedTestRunId);
                        }

                        transaction.Commit();
                    }
                    catch
                    {
                        transaction.Rollback();
                        throw;
                    }
                }
            }
        }

        private void ImportTable(
            SqlConnection connection,
            SqlTransaction transaction,
            TableDefinition definition,
            DataTable source,
            int? sharedTestRunId)
        {
            DataTable destinationData = new DataTable();

            // Include only columns that should be explicitly inserted.
            foreach (ColumnMapping mapping in definition.Columns)
            {
                if (!source.Columns.Contains(mapping.Source))
                    throw new InvalidOperationException(
                        $"Source column '{mapping.Source}' " +
                        $"not found in '{source.TableName}'.");

                string destinationName =
                    string.IsNullOrWhiteSpace(mapping.Destination)
                        ? mapping.Source
                        : mapping.Destination;

                destinationData.Columns.Add(
                    destinationName,
                    source.Columns[mapping.Source].DataType);
            }

            // Add generated columns that are not identity columns.
            foreach (GeneratedColumn generated
                     in definition.GeneratedColumns)
            {
                if (generated.Type == GeneratedColumnType.Identity)
                    continue;

                if (generated.Type == GeneratedColumnType.Default)
                    continue;

                if (generated.Type == GeneratedColumnType.SharedValue)
                {
                    if (sharedTestRunId == null)
                        throw new InvalidOperationException(
                            $"Shared TestRunID is required for " +
                            $"table '{definition.Name}'.");

                    if (!destinationData.Columns.Contains(generated.Name))
                    {
                        destinationData.Columns.Add(
                            generated.Name, typeof(int));
                    }
                }
            }

            foreach (DataRow sourceRow in source.Rows)
            {
                DataRow destinationRow =
                    destinationData.NewRow();

                foreach (ColumnMapping mapping in definition.Columns)
                {
                    string destinationName =
                        string.IsNullOrWhiteSpace(mapping.Destination)
                            ? mapping.Source
                            : mapping.Destination;

                    destinationRow[destinationName] =
                        sourceRow[mapping.Source] ?? DBNull.Value;
                }

                foreach (GeneratedColumn generated
                         in definition.GeneratedColumns)
                {
                    if (generated.Type ==
                        GeneratedColumnType.SharedValue)
                    {
                        destinationRow[generated.Name] =
                            sharedTestRunId.Value;
                    }
                }

                destinationData.Rows.Add(destinationRow);
            }

            if (destinationData.Rows.Count == 0)
                return;

            string schema = string.IsNullOrWhiteSpace(definition.Schema)
                ? "dbo"
                : definition.Schema;

            string destinationTable =
                GetDestinationTableName(definition);

            using (var bulkCopy = new SqlBulkCopy(
                connection,
                SqlBulkCopyOptions.CheckConstraints,
                transaction))
            {
                bulkCopy.DestinationTableName =
                    $"[{schema}].[{destinationTable}]";

                bulkCopy.BatchSize = 1000;
                bulkCopy.BulkCopyTimeout = 0;

                foreach (DataColumn column in destinationData.Columns)
                {
                    bulkCopy.ColumnMappings.Add(
                        column.ColumnName,
                        column.ColumnName);
                }

                bulkCopy.WriteToServer(destinationData);
            }
        }

        private string GetDestinationTableName(
            TableDefinition definition)
        {
            if (definition.DestinationTable.Contains("."))
            {
                string[] parts =
                    definition.DestinationTable.Split('.');

                if (parts.Length != 2)
                    throw new InvalidOperationException(
                        $"Invalid destination table: " +
                        definition.DestinationTable);

                return parts[1];
            }

            return definition.DestinationTable;
        }
    }
}





















I recommend updating your existing classes rather than creating a separate configuration model. Your current design is already a good foundation for a metadata-driven database importer.

I would make the following changes:

1. **Identity:** Add an `Identity` property. When enabled, the primary key column becomes `IDENTITY(1,1)`.
2. **Primary key:** Support both single-column and composite primary keys.
3. **Multiple unique keys:** Replace the single `UniqueKey` string with `List<UniqueKeyDefinition>`.
4. **Optional parent:** Root and Property tables can exist without a parent.
5. **Foreign key:** Generate the relationship from `Parent` and `JoinConditions`.
6. **Dependency ordering:** Keep your existing parent-first ordering and circular-dependency detection.
7. **Validation:** Validate identity, keys, columns, and parent relationships before importing.

## **1. Recommended XML configuration**

For a table without a parent:

```
<Table
    name="TestRunProperty"
    type="Property"
    sourceTable="TestRunProperty"
    destinationTable="TestRunProperty"
    primaryKey="PropertyID"
    identity="true">

    <UniqueKeys>
        <UniqueKey columns="PropertyID,TestRunID" />
        <UniqueKey columns="PropertyName,TestRunID" />
    </UniqueKeys>

    <Columns>
        <Column source="PropertyID" />
        <Column source="TestRunID" />
        <Column source="PropertyName" />
    </Columns>
</Table>
```

For a table with a parent:

```
<Table
    name="MOSS"
    type="Child"
    sourceTable="MOSS_table"
    destinationTable="SDA_MOSS"
    parent="TestRunProperty"
    primaryKey="MOSS_ID"
    identity="true">

    <UniqueKeys>
        <UniqueKey columns="PropertyID,TestRunID" />
        <UniqueKey columns="MOSS_Name,TestRunID" />
    </UniqueKeys>

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
        <Column source="MOSS_Name" />
    </Columns>
</Table>
```

Notice that `UniqueKeys` can contain as many unique constraints as needed.

## **2. Complete updated TableDefinition classes**

Replace your existing configuration classes with the following.

```
using System;
using System.Collections.Generic;
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

        // =========================================
        // LOAD CONFIGURATION
        // =========================================

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

        // =========================================
        // PARSE TABLE
        // =========================================

        private static TableDefinition ParseTable(XElement element)
        {
            string typeValue = RequiredAttribute(element, "type");

            if (!Enum.TryParse(
                typeValue,
                true,
                out TableType tableType))
            {
                throw new InvalidOperationException(
                    $"Invalid table type '{typeValue}'.");
            }

            var table = new TableDefinition
            {
                Name = RequiredAttribute(element, "name"),

                Type = tableType,

                SourceTable =
                    RequiredAttribute(element, "sourceTable"),

                DestinationTable =
                    RequiredAttribute(element, "destinationTable"),

                Parent = (string)element.Attribute("parent"),

                PrimaryKey = ParseColumns(
                    (string)element.Attribute("primaryKey")),

                Identity = ParseBooleanAttribute(
                    element, "identity", false),

                JoinOperator = "AND"
            };

            // -------------------------------------
            // UNIQUE KEYS
            // -------------------------------------

            XElement uniqueKeysElement =
                element.Element("UniqueKeys");

            if (uniqueKeysElement != null)
            {
                foreach (XElement uniqueElement
                    in uniqueKeysElement.Elements("UniqueKey"))
                {
                    string columns =
                        RequiredAttribute(uniqueElement, "columns");

                    table.UniqueKeys.Add(new UniqueKeyDefinition
                    {
                        Columns = ParseColumns(columns)
                    });
                }
            }

            // Backward compatibility with old XML:
            // uniqueKey="Column1,Column2"
            string legacyUniqueKey =
                (string)element.Attribute("uniqueKey");

            if (!string.IsNullOrWhiteSpace(legacyUniqueKey))
            {
                table.UniqueKeys.Add(new UniqueKeyDefinition
                {
                    Columns = ParseColumns(legacyUniqueKey)
                });
            }

            // -------------------------------------
            // JOIN CONDITIONS / FOREIGN KEY
            // -------------------------------------

            XElement joinElement =
                element.Element("JoinConditions");

            if (joinElement != null)
            {
                table.JoinOperator =
                    ((string)joinElement.Attribute("operator") ?? "AND")
                    .ToUpperInvariant();

                foreach (XElement condition
                    in joinElement.Elements("Condition"))
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

            // -------------------------------------
            // COLUMN MAPPINGS
            // -------------------------------------

            XElement columnsElement = element.Element("Columns");

            if (columnsElement != null)
            {
                foreach (XElement column
                    in columnsElement.Elements("Column"))
                {
                    string source =
                        RequiredAttribute(column, "source");

                    table.Columns.Add(new ColumnMapping
                    {
                        Source = source,

                        Destination =
                            (string)column.Attribute("destination")
                            ?? source
                    });
                }
            }

            return table;
        }

        // =========================================
        // HELPER METHODS
        // =========================================

        private static string RequiredAttribute(
            XElement element,
            string attributeName)
        {
            string value =
                (string)element.Attribute(attributeName);

            if (string.IsNullOrWhiteSpace(value))
            {
                throw new InvalidOperationException(
                    $"Element <{element.Name}> requires attribute " +
                    $"'{attributeName}'.");
            }

            return value.Trim();
        }

        private static bool ParseBooleanAttribute(
            XElement element,
            string attributeName,
            bool defaultValue)
        {
            string value = (string)element.Attribute(attributeName);

            if (string.IsNullOrWhiteSpace(value))
                return defaultValue;

            if (!bool.TryParse(value, out bool result))
            {
                throw new InvalidOperationException(
                    $"Invalid Boolean value '{value}' for " +
                    $"attribute '{attributeName}'.");
            }

            return result;
        }

        private static List<string> ParseColumns(string value)
        {
            if (string.IsNullOrWhiteSpace(value))
                return new List<string>();

            return value.Split(',')
                .Select(c => c.Trim())
                .Where(c => !string.IsNullOrWhiteSpace(c))
                .ToList();
        }

        // =========================================
        // VALIDATE CONFIGURATION
        // =========================================

        public void Validate()
        {
            var names = new HashSet<string>(
                StringComparer.OrdinalIgnoreCase);

            // First pass: individual table validation
            foreach (var table in Tables)
            {
                if (!names.Add(table.Name))
                {
                    throw new InvalidOperationException(
                        $"Duplicate table definition: {table.Name}");
                }

                if (!Enum.IsDefined(typeof(TableType), table.Type))
                {
                    throw new InvalidOperationException(
                        $"Invalid table type for '{table.Name}'.");
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
                        $"Invalid JoinConditions operator for " +
                        $"'{table.Name}'.");
                }

                if (table.Columns.Count == 0)
                {
                    throw new InvalidOperationException(
                        $"Table '{table.Name}' has no column mappings.");
                }

                // Destination column names must be unique
                var destinationColumns = new HashSet<string>(
                    StringComparer.OrdinalIgnoreCase);

                foreach (var column in table.Columns)
                {
                    if (!destinationColumns.Add(column.Destination))
                    {
                        throw new InvalidOperationException(
                            $"Duplicate destination column " +
                            $"'{column.Destination}' in '{table.Name}'.");
                    }
                }

                // Primary key validation
                ValidateKeyColumns(
                    table,
                    table.PrimaryKey,
                    "Primary key");

                // Identity validation
                if (table.Identity)
                {
                    if (table.PrimaryKey.Count != 1)
                    {
                        throw new InvalidOperationException(
                            $"Identity table '{table.Name}' must have " +
                            "exactly one primary key column.");
                    }
                }

                // Unique key validation
                foreach (var uniqueKey in table.UniqueKeys)
                {
                    ValidateKeyColumns(
                        table,
                        uniqueKey.Columns,
                        "Unique key");
                }

                // Parent and foreign key validation
                if (table.JoinConditions.Count > 0 &&
                    string.IsNullOrWhiteSpace(table.Parent))
                {
                    throw new InvalidOperationException(
                        $"Table '{table.Name}' defines JoinConditions " +
                        "but has no parent.");
                }

                if (!string.IsNullOrWhiteSpace(table.Parent) &&
                    table.JoinConditions.Count == 0)
                {
                    throw new InvalidOperationException(
                        $"Table '{table.Name}' defines a parent but " +
                        "has no JoinConditions.");
                }

                if (table.JoinConditions.Count > 0 &&
                    table.JoinOperator != "AND")
                {
                    throw new InvalidOperationException(
                        $"Foreign key for '{table.Name}' must use " +
                        "AND conditions. SQL Server foreign keys " +
                        "do not support OR relationships.");
                }

                foreach (var condition in table.JoinConditions)
                {
                    if (!destinationColumns.Contains(
                        condition.ChildColumn))
                    {
                        throw new InvalidOperationException(
                            $"Foreign key child column " +
                            $"'{condition.ChildColumn}' does not exist " +
                            $"in '{table.Name}'.");
                    }
                }
            }

            // Second pass: validate parent relationships
            foreach (var table in Tables)
            {
                if (string.IsNullOrWhiteSpace(table.Parent))
                    continue;

                TableDefinition parent = Tables.FirstOrDefault(
                    x => x.Name.Equals(
                        table.Parent,
                        StringComparison.OrdinalIgnoreCase));

                if (parent == null)
                {
                    throw new InvalidOperationException(
                        $"Parent '{table.Parent}' for table " +
                        $"'{table.Name}' was not defined.");
                }

                foreach (var condition in table.JoinConditions)
                {
                    if (!parent.Columns.Any(c =>
                        c.Destination.Equals(
                            condition.ParentColumn,
                            StringComparison.OrdinalIgnoreCase)))
                    {
                        throw new InvalidOperationException(
                            $"Parent column '{condition.ParentColumn}' " +
                            $"does not exist in '{parent.Name}'.");
                    }
                }

                // SQL Server requires referenced parent columns
                // to be a primary key or unique key.
                var parentColumns = table.JoinConditions
                    .Select(c => c.ParentColumn)
                    .ToHashSet(StringComparer.OrdinalIgnoreCase);

                bool validReference =
                    SameKey(parent.PrimaryKey, parentColumns) ||
                    parent.UniqueKeys.Any(u =>
                        SameKey(u.Columns, parentColumns));

                if (!validReference)
                {
                    throw new InvalidOperationException(
                        $"Foreign key for '{table.Name}' references " +
                        $"columns in '{parent.Name}' that are not " +
                        "a primary key or unique key.");
                }
            }
        }

        private static void ValidateKeyColumns(
            TableDefinition table,
            List<string> keyColumns,
            string keyType)
        {
            if (keyColumns == null || keyColumns.Count == 0)
                return;

            if (keyColumns.Distinct(
                StringComparer.OrdinalIgnoreCase).Count()
                != keyColumns.Count)
            {
                throw new InvalidOperationException(
                    $"Duplicate columns in {keyType} of '{table.Name}'.");
            }

            foreach (string keyColumn in keyColumns)
            {
                if (!table.Columns.Any(c =>
                    c.Destination.Equals(
                        keyColumn,
                        StringComparison.OrdinalIgnoreCase)))
                {
                    throw new InvalidOperationException(
                        $"{keyType} column '{keyColumn}' " +
                        $"does not exist in '{table.Name}'.");
                }
            }
        }

        private static bool SameKey(
            IEnumerable<string> first,
            IEnumerable<string> second)
        {
            var firstSet = new HashSet<string>(
                first,
                StringComparer.OrdinalIgnoreCase);

            var secondSet = new HashSet<string>(
                second,
                StringComparer.OrdinalIgnoreCase);

            return firstSet.SetEquals(secondSet);
        }

        // =========================================
        // TABLE DEPENDENCY ORDER
        // =========================================

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
                    $"Circular table dependency detected at " +
                    $"'{table.Name}'.");
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

    // =============================================
    // TABLE DEFINITION
    // =============================================

    public class TableDefinition
    {
        public string Name { get; set; }

        public TableType Type { get; set; }

        public string SourceTable { get; set; }

        public string DestinationTable { get; set; }

        public string Parent { get; set; }

        // Supports single or composite primary keys
        public List<string> PrimaryKey { get; set; }
            = new List<string>();

        // SQL Server IDENTITY(1,1)
        public bool Identity { get; set; }

        // Supports multiple unique constraints
        public List<UniqueKeyDefinition> UniqueKeys { get; set; }
            = new List<UniqueKeyDefinition>();

        public string JoinOperator { get; set; } = "AND";

        // Parent-child relationship
        public List<JoinCondition> JoinConditions { get; set; }
            = new List<JoinCondition>();

        // Source-to-destination column mappings
        public List<ColumnMapping> Columns { get; set; }
            = new List<ColumnMapping>();
    }

    // =============================================
    // UNIQUE KEY DEFINITION
    // =============================================

    public class UniqueKeyDefinition
    {
        public List<string> Columns { get; set; }
            = new List<string>();
    }

    // =============================================
    // FOREIGN KEY / JOIN CONDITION
    // =============================================

    public class JoinCondition
    {
        public string ParentColumn { get; set; }

        public string ChildColumn { get; set; }
    }

    // =============================================
    // COLUMN MAPPING
    // =============================================

    public class ColumnMapping
    {
        public string Source { get; set; }

        public string Destination { get; set; }
    }
}
```

## **3. Important implementation notes**

There are three things to consider when connecting this configuration class to your table creation and data import methods.

**A. Identity and source IDs**

When `Identity = true`, SQL Server generates a new primary key. Your importer must not insert the SQLite primary key value.

For example:

| SQLite MOSS_ID | SQL Server MOSS_ID |
| -------------- | ------------------ |
| 101            | 1                  |
| 102            | 2                  |
| 103            | 3                  |

**B. Foreign keys and identity mapping**

This is particularly important for your parent-child tables.

If `TestRunProperty.PropertyID` is generated by SQL Server, the child table cannot simply copy the original SQLite `PropertyID`.

You will need an ID mapping between SQLite and SQL Server:

```
SQLite Parent ID  →  SQL Server Parent ID

101               →  1
102               →  2
103               →  3
```

Your importer must use this mapping when inserting child records. Otherwise, the foreign key will fail.

**C. Foreign key constraints**

SQL Server requires the referenced parent columns to have a primary key or unique constraint. The order of the referenced columns must also match the corresponding candidate key definition.

For example:

```
UNIQUE (PropertyID, TestRunID)
```

should be referenced as:

```
FOREIGN KEY (PropertyID, TestRunID)
REFERENCES TestRunProperty (PropertyID, TestRunID)
```

## **4. Final architecture recommendation**

Keep responsibilities separated:

| Class                 | Responsibility                             |
| --------------------- | ------------------------------------------ |
| `AggregatorConfig`    | Load and validate XML                      |
| `TableDefinition`     | Store table metadata                       |
| `UniqueKeyDefinition` | Store multiple unique constraints          |
| `JoinCondition`       | Define foreign-key relationships           |
| `ColumnMapping`       | Map SQLite to SQL Server columns           |
| `TableCreator`        | Generate SQL Server tables and constraints |
| `DataImporter`        | Import data and handle identity mapping    |

One important distinction: the code above updates your configuration model and validation. It does not yet implement the SQL Server table creation or the parent identity mapping. Those belong in `TableCreator` and `DataImporter`, respectively.



---


Below is a complete SQL Server table-creation implementation. It assumes:

- Your SQLite data has already been loaded into a `DataSet`.
- Each `DataTable` contains the source table's columns and rows.
- Your `AggregatorConfig` contains the table definitions and constraints.
- You want to create SQL Server tables with **column types, primary keys, identity columns, multiple unique keys, and foreign keys**.
- You are not inserting data yet.

The implementation uses the `DataColumn.DataType` property to determine SQL Server column types. You can override any inferred type in your configuration using `SqlType`.

**Important:** A `DataTable` does not necessarily preserve the original SQLite declared column type. For example, SQLite `NUMERIC` might appear as a .NET `Decimal`. If you need a specific SQL Server type, set `SqlType` explicitly.

## **1. Configuration models**

Create `AggregatorConfig.cs`:

```

using System;
using System.Collections.Generic;

namespace DataAggregator
{
    public class AggregatorConfig
    {
        public List<TableDefinition> Tables { get; set; }
            = new List<TableDefinition>();

        public TableDefinition GetTable(string name)
        {
            return Tables.Find(t =>
                string.Equals(t.Name, name,
                    StringComparison.OrdinalIgnoreCase));
        }
    }

    public class TableDefinition
    {
        // Logical name used to identify this table in the configuration.
        public string Name { get; set; }

        // Name of the SQLite table / DataTable.
        public string SourceTable { get; set; }

        // SQL Server destination table.
        // Can be "MyTable" or "dbo.MyTable".
        public string DestinationTable { get; set; }

        // Optional schema. Defaults to dbo.
        public string Schema { get; set; } = "dbo";

        // One or more destination column names.
        public List<string> PrimaryKey { get; set; }
            = new List<string>();

        // True only when the single primary key is SQL IDENTITY.
        public bool Identity { get; set; }

        public List<UniqueKeyDefinition> UniqueKeys { get; set; }
            = new List<UniqueKeyDefinition>();

        // Optional parent table and relationship.
        public string Parent { get; set; }

        public List<JoinCondition> JoinConditions { get; set; }
            = new List<JoinCondition>();

        // Empty means use all source columns with their original names.
        public List<ColumnMapping> Columns { get; set; }
            = new List<ColumnMapping>();
    }

    public class UniqueKeyDefinition
    {
        public List<string> Columns { get; set; }
            = new List<string>();
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

        // Optional SQL Server type override.
        // Examples: BIGINT, NVARCHAR(200), DECIMAL(18,2).
        public string SqlType { get; set; }

        // Null means use DataColumn.AllowDBNull.
        public bool? Nullable { get; set; }
    }
}

```

## **2. SQL Server type mapper**

Create `SqlTypeMapper.cs`.

This maps the .NET types in your existing `DataTable` to SQL Server types. Explicit `SqlType` configuration takes priority over automatic mapping.

```

using System;
using System.Data;

namespace DataAggregator
{
    public static class SqlTypeMapper
    {
        public static string GetSqlType(
            DataColumn dataColumn,
            ColumnMapping mapping)
        {
            // Explicit configuration always takes priority.
            if (!string.IsNullOrWhiteSpace(mapping?.SqlType))
            {
                ValidateSqlType(mapping.SqlType);
                return mapping.SqlType;
            }

            Type type = dataColumn.DataType;

            if (type == typeof(string))
            {
                int length = dataColumn.MaxLength;

                if (length > 0 && length <= 4000)
                    return $"NVARCHAR({length})";

                return "NVARCHAR(MAX)";
            }

            if (type == typeof(long))
                return "BIGINT";

            if (type == typeof(int))
                return "INT";

            if (type == typeof(short))
                return "SMALLINT";

            if (type == typeof(byte))
                return "TINYINT";

            if (type == typeof(bool))
                return "BIT";

            if (type == typeof(decimal))
                return "DECIMAL(18,4)";

            if (type == typeof(double))
                return "FLOAT";

            if (type == typeof(float))
                return "REAL";

            if (type == typeof(DateTime))
                return "DATETIME2";

            if (type == typeof(DateTimeOffset))
                return "DATETIMEOFFSET";

            if (type == typeof(TimeSpan))
                return "TIME";

            if (type == typeof(Guid))
                return "UNIQUEIDENTIFIER";

            if (type == typeof(byte[]))
                return "VARBINARY(MAX)";

            if (type == typeof(char))
                return "NCHAR(1)";

            if (type.IsEnum)
                return "INT";

            throw new NotSupportedException(
                $"Unsupported DataColumn type '{type.FullName}' " +
                $"for column '{dataColumn.ColumnName}'. " +
                "Specify SqlType in the configuration.");
        }

        private static void ValidateSqlType(string sqlType)
        {
            // Prevent arbitrary SQL fragments in the configured type.
            string value = sqlType.Trim().ToUpperInvariant();

            string[] allowed =
            {
                "BIGINT", "INT", "SMALLINT", "TINYINT", "BIT",
                "FLOAT", "REAL", "DATE", "DATETIME",
                "DATETIME2", "DATETIMEOFFSET", "TIME",
                "UNIQUEIDENTIFIER", "MONEY", "SMALLMONEY",
                "NVARCHAR(MAX)", "VARCHAR(MAX)",
                "VARBINARY(MAX)"
            };

            foreach (string item in allowed)
            {
                if (value == item)
                    return;
            }

            if (System.Text.RegularExpressions.Regex.IsMatch(
                value,
                @"^(N?VARCHAR|N?CHAR)\([1-9][0-9]{0,3}\)$"))
                return;

            if (System.Text.RegularExpressions.Regex.IsMatch(
                value,
                @"^(DECIMAL|NUMERIC)\([1-9][0-9]?,[0-9]{1,2}\)$"))
                return;

            if (System.Text.RegularExpressions.Regex.IsMatch(
                value,
                @"^VARBINARY\([1-9][0-9]*\)$"))
                return;

            throw new InvalidOperationException(
                $"Invalid or unsupported SQL type: {sqlType}");
        }
    }
}

```

# Transfer Data from SQLite to MSSql  

## **3. SQL Server table creator**

Create `SqlServerTableCreator.cs`.

This is the main implementation. It:

1. Finds the corresponding `DataTable` for each configured source table.
2. Builds SQL Server column definitions.
3. Creates primary keys.
4. Creates identity columns when configured.
5. Creates all configured unique constraints.
6. Creates foreign keys after all tables exist.
7. Uses a transaction so a failure rolls back the table creation.
8. Validates the configured relationships before creating the tables.

```

using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Data.SqlClient;

namespace DataAggregator
{
    public class SqlServerTableCreator
    {
        private readonly string _connectionString;

        public SqlServerTableCreator(string connectionString)
        {
            _connectionString = connectionString;
        }

        public void CreateTables(
            AggregatorConfig config,
            DataSet sourceData)
        {
            if (config == null)
                throw new ArgumentNullException(nameof(config));

            if (sourceData == null)
                throw new ArgumentNullException(nameof(sourceData));

            if (config.Tables.Count == 0)
                throw new InvalidOperationException(
                    "No table definitions were configured.");

            // Resolve DataTables and validate all definitions first.
            var resolved = ResolveTables(config, sourceData);

            ValidateConfiguration(config, resolved);

            using (var connection =
                new SqlConnection(_connectionString))
            {
                connection.Open();

                using (SqlTransaction transaction =
                    connection.BeginTransaction())
                {
                    try
                    {
                        // Create all destination tables first.
                        foreach (var item in resolved)
                        {
                            CreateTable(
                                connection,
                                transaction,
                                item.Definition,
                                item.DataTable,
                                item.Columns);
                        }

                        // Add foreign keys only after all tables exist.
                        foreach (var item in resolved)
                        {
                            if (!string.IsNullOrWhiteSpace(
                                    item.Definition.Parent) &&
                                item.Definition.JoinConditions.Count > 0)
                            {
                                CreateForeignKey(
                                    connection,
                                    transaction,
                                    config,
                                    item.Definition);
                            }
                        }

                        transaction.Commit();
                    }
                    catch
                    {
                        transaction.Rollback();
                        throw;
                    }
                }
            }
        }

        private class ResolvedTable
        {
            public TableDefinition Definition { get; set; }

            public DataTable DataTable { get; set; }

            public List<ResolvedColumn> Columns { get; set; }
        }

        private class ResolvedColumn
        {
            public string SourceName { get; set; }

            public string DestinationName { get; set; }

            public string SqlType { get; set; }

            public bool AllowNull { get; set; }

            public DataColumn DataColumn { get; set; }
        }

        private List<ResolvedTable> ResolveTables(
            AggregatorConfig config,
            DataSet sourceData)
        {
            var result = new List<ResolvedTable>();

            foreach (TableDefinition definition in config.Tables)
            {
                if (string.IsNullOrWhiteSpace(definition.SourceTable))
                    throw new InvalidOperationException(
                        $"SourceTable is missing for '{definition.Name}'.");

                if (string.IsNullOrWhiteSpace(definition.DestinationTable))
                    throw new InvalidOperationException(
                        $"DestinationTable is missing for '{definition.Name}'.");

                if (!sourceData.Tables.Contains(definition.SourceTable))
                    throw new InvalidOperationException(
                        $"DataTable '{definition.SourceTable}' was not found.");

                DataTable dataTable =
                    sourceData.Tables[definition.SourceTable];

                var columns = ResolveColumns(definition, dataTable);

                result.Add(new ResolvedTable
                {
                    Definition = definition,
                    DataTable = dataTable,
                    Columns = columns
                });
            }

            return result;
        }

        private List<ResolvedColumn> ResolveColumns(
            TableDefinition definition,
            DataTable dataTable)
        {
            var result = new List<ResolvedColumn>();

            // If no column mapping exists, use every DataTable column.
            if (definition.Columns == null ||
                definition.Columns.Count == 0)
            {
                foreach (DataColumn dataColumn in dataTable.Columns)
                {
                    result.Add(new ResolvedColumn
                    {
                        SourceName = dataColumn.ColumnName,
                        DestinationName = dataColumn.ColumnName,
                        SqlType = SqlTypeMapper.GetSqlType(
                            dataColumn, null),
                        AllowNull = dataColumn.AllowDBNull,
                        DataColumn = dataColumn
                    });
                }

                return result;
            }

            foreach (ColumnMapping mapping in definition.Columns)
            {
                if (string.IsNullOrWhiteSpace(mapping.Source))
                    throw new InvalidOperationException(
                        $"A source column is missing in '{definition.Name}'.");

                if (!dataTable.Columns.Contains(mapping.Source))
                    throw new InvalidOperationException(
                        $"Source column '{mapping.Source}' was not found " +
                        $"in DataTable '{dataTable.TableName}'.");

                DataColumn dataColumn =
                    dataTable.Columns[mapping.Source];

                string destination =
                    string.IsNullOrWhiteSpace(mapping.Destination)
                        ? mapping.Source
                        : mapping.Destination;

                result.Add(new ResolvedColumn
                {
                    SourceName = mapping.Source,
                    DestinationName = destination,
                    SqlType = SqlTypeMapper.GetSqlType(
                        dataColumn, mapping),
                    AllowNull = mapping.Nullable ??
                                dataColumn.AllowDBNull,
                    DataColumn = dataColumn
                });
            }

            return result;
        }

        private void ValidateConfiguration(
            AggregatorConfig config,
            List<ResolvedTable> resolved)
        {
            foreach (ResolvedTable item in resolved)
            {
                TableDefinition table = item.Definition;

                var destinationColumns = new HashSet<string>(
                    item.Columns.Select(c => c.DestinationName),
                    StringComparer.OrdinalIgnoreCase);

                if (destinationColumns.Count != item.Columns.Count)
                    throw new InvalidOperationException(
                        $"Duplicate destination column mapping in '{table.Name}'.");

                if (item.Columns.Count == 0)
                    throw new InvalidOperationException(
                        $"Table '{table.Name}' has no columns.");

                ValidateKeyColumns(
                    table.Name, "PrimaryKey",
                    table.PrimaryKey, destinationColumns);

                foreach (UniqueKeyDefinition uniqueKey in table.UniqueKeys)
                {
                    ValidateKeyColumns(
                        table.Name, "UniqueKey",
                        uniqueKey.Columns, destinationColumns);
                }

                if (table.Identity)
                {
                    if (table.PrimaryKey.Count != 1)
                        throw new InvalidOperationException(
                            $"Identity table '{table.Name}' must have " +
                            "exactly one primary key column.");

                    ResolvedColumn identityColumn =
                        item.Columns.First(c =>
                            c.DestinationName.Equals(
                                table.PrimaryKey[0],
                                StringComparison.OrdinalIgnoreCase));

                    if (!new[] { "INT", "BIGINT", "SMALLINT", "TINYINT" }
                        .Contains(identityColumn.SqlType.ToUpperInvariant()))
                    {
                        throw new InvalidOperationException(
                            $"Identity column '{identityColumn.DestinationName}' " +
                            "must use INT, BIGINT, SMALLINT or TINYINT.");
                    }
                }

                if (table.JoinConditions.Count > 0)
                {
                    if (string.IsNullOrWhiteSpace(table.Parent))
                        throw new InvalidOperationException(
                            $"Table '{table.Name}' has JoinConditions " +
                            "but no Parent.");

                    TableDefinition parent =
                        config.GetTable(table.Parent);

                    if (parent == null)
                        throw new InvalidOperationException(
                            $"Parent '{table.Parent}' was not found.");

                    foreach (JoinCondition condition in table.JoinConditions)
                    {
                        if (!destinationColumns.Contains(condition.ChildColumn))
                            throw new InvalidOperationException(
                                $"Foreign key child column " +
                                $"'{condition.ChildColumn}' was not found " +
                                $"in '{table.Name}'.");
                    }

                    ValidateParentKey(config, table, parent);
                    ValidateForeignKeyTypes(
                        config, resolved, table, parent);
                }
            }
        }

        private void ValidateKeyColumns(
            string tableName,
            string keyName,
            List<string> columns,
            HashSet<string> availableColumns)
        {
            if (columns == null || columns.Count == 0)
                return;

            foreach (string column in columns)
            {
                if (!availableColumns.Contains(column))
                    throw new InvalidOperationException(
                        $"{keyName} column '{column}' does not exist " +
                        $"in table '{tableName}'.");
            }
        }

        private void ValidateParentKey(
            AggregatorConfig config,
            TableDefinition child,
            TableDefinition parent)
        {
            List<string> referencedColumns =
                child.JoinConditions
                    .Select(c => c.ParentColumn)
                    .ToList();

            // SQL Server foreign keys must reference a primary key
            // or a unique key with the same columns in the same order.
            bool matchesPrimary =
                SameOrderedColumns(
                    referencedColumns, parent.PrimaryKey);

            bool matchesUnique = parent.UniqueKeys.Any(
                key => SameOrderedColumns(
                    referencedColumns, key.Columns));

            if (!matchesPrimary && !matchesUnique)
            {
                throw new InvalidOperationException(
                    $"Foreign key from '{child.Name}' to '{parent.Name}' " +
                    "must reference the parent's primary key or one " +
                    "of its unique keys, in the same column order.");
            }
        }

        private bool SameOrderedColumns(
            List<string> first,
            List<string> second)
        {
            if (first == null || second == null)
                return false;

            if (first.Count != second.Count)
                return false;

            for (int i = 0; i < first.Count; i++)
            {
                if (!first[i].Equals(
                    second[i],
                    StringComparison.OrdinalIgnoreCase))
                    return false;
            }

            return true;
        }

        private void ValidateForeignKeyTypes(
            AggregatorConfig config,
            List<ResolvedTable> resolved,
            TableDefinition child,
            TableDefinition parent)
        {
            ResolvedTable childResolved =
                resolved.First(x => x.Definition == child);

            ResolvedTable parentResolved =
                resolved.First(x => x.Definition == parent);

            foreach (JoinCondition condition in child.JoinConditions)
            {
                ResolvedColumn childColumn =
                    childResolved.Columns.First(c =>
                        c.DestinationName.Equals(
                            condition.ChildColumn,
                            StringComparison.OrdinalIgnoreCase));

                ResolvedColumn parentColumn =
                    parentResolved.Columns.FirstOrDefault(c =>
                        c.DestinationName.Equals(
                            condition.ParentColumn,
                            StringComparison.OrdinalIgnoreCase));

                if (parentColumn == null)
                    throw new InvalidOperationException(
                        $"Parent column '{condition.ParentColumn}' " +
                        $"was not found in '{parent.Name}'.");

                if (!childColumn.SqlType.Equals(
                    parentColumn.SqlType,
                    StringComparison.OrdinalIgnoreCase))
                {
                    throw new InvalidOperationException(
                        $"Foreign key type mismatch: " +
                        $"'{child.Name}.{condition.ChildColumn}' is " +
                        $"{childColumn.SqlType}, but " +
                        $"'{parent.Name}.{condition.ParentColumn}' is " +
                        $"{parentColumn.SqlType}.");
                }
            }
        }

        private void CreateTable(
            SqlConnection connection,
            SqlTransaction transaction,
            TableDefinition definition,
            DataTable dataTable,
            List<ResolvedColumn> columns)
        {
            string schema = GetSchema(definition);
            string tableName = GetTableName(definition);

            string qualifiedName =
                $"{Quote(schema)}.{Quote(tableName)}";

            string objectName = $"{schema}.{tableName}";

            using (var check = new SqlCommand(
                "SELECT OBJECT_ID(@name, 'U')",
                connection,
                transaction))
            {
                check.Parameters.AddWithValue("@name", objectName);

                object existing = check.ExecuteScalar();

                if (existing != null && existing != DBNull.Value)
                    throw new InvalidOperationException(
                        $"SQL Server table '{objectName}' already exists.");
            }

            var definitions = new List<string>();

            foreach (ResolvedColumn column in columns)
            {
                bool isPrimaryKey =
                    definition.PrimaryKey.Any(pk =>
                        pk.Equals(
                            column.DestinationName,
                            StringComparison.OrdinalIgnoreCase));

                string sql = $"{Quote(column.DestinationName)} " +
                             column.SqlType;

                if (definition.Identity && isPrimaryKey)
                    sql += " IDENTITY(1,1)";

                bool allowNull =
                    isPrimaryKey ? false : column.AllowNull;

                sql += allowNull ? " NULL" : " NOT NULL";

                definitions.Add(sql);
            }

            // Primary key constraint.
            if (definition.PrimaryKey.Count > 0)
            {
                string primaryColumns = string.Join(
                    ", ",
                    definition.PrimaryKey.Select(Quote));

                definitions.Add(
                    $"CONSTRAINT {Quote(ConstraintName("PK", tableName, "1"))} " +
                    $"PRIMARY KEY ({primaryColumns})");
            }

            // Multiple unique constraints.
            for (int i = 0; i < definition.UniqueKeys.Count; i++)
            {
                UniqueKeyDefinition unique =
                    definition.UniqueKeys[i];

                string uniqueColumns = string.Join(
                    ", ",
                    unique.Columns.Select(Quote));

                definitions.Add(
                    $"CONSTRAINT {Quote(ConstraintName("UQ", tableName, (i + 1).ToString()))} " +
                    $"UNIQUE ({uniqueColumns})");
            }

            string sqlCreate =
                $"CREATE TABLE {qualifiedName} (" +
                string.Join(", ", definitions) +
                ");";

            using (var command = new SqlCommand(
                sqlCreate, connection, transaction))
            {
                command.ExecuteNonQuery();
            }
        }

        private void CreateForeignKey(
            SqlConnection connection,
            SqlTransaction transaction,
            AggregatorConfig config,
            TableDefinition child)
        {
            TableDefinition parent = config.GetTable(child.Parent);

            string childSchema = GetSchema(child);
            string childTable = GetTableName(child);

            string parentSchema = GetSchema(parent);
            string parentTable = GetTableName(parent);

            string childColumns = string.Join(
                ", ",
                child.JoinConditions.Select(
                    c => Quote(c.ChildColumn)));

            string parentColumns = string.Join(
                ", ",
                child.JoinConditions.Select(
                    c => Quote(c.ParentColumn)));

            string constraintName = ConstraintName(
                "FK",
                childTable,
                parentTable);

            string sql =
                $"ALTER TABLE {Quote(childSchema)}.{Quote(childTable)} " +
                $"ADD CONSTRAINT {Quote(constraintName)} " +
                $"FOREIGN KEY ({childColumns}) " +
                $"REFERENCES {Quote(parentSchema)}.{Quote(parentTable)} " +
                $"({parentColumns});";

            using (var command = new SqlCommand(
                sql, connection, transaction))
            {
                command.ExecuteNonQuery();
            }
        }

        private string GetSchema(TableDefinition table)
        {
            string schema = string.IsNullOrWhiteSpace(table.Schema)
                ? "dbo"
                : table.Schema;

            string destination = table.DestinationTable;

            if (destination.Contains("."))
            {
                string[] parts = destination.Split('.');

                if (parts.Length != 2)
                    throw new InvalidOperationException(
                        $"Invalid destination table name: {destination}");

                schema = parts[0];
            }

            return schema;
        }

        private string GetTableName(TableDefinition table)
        {
            string destination = table.DestinationTable;

            if (destination.Contains("."))
            {
                string[] parts = destination.Split('.');

                if (parts.Length != 2)
                    throw new InvalidOperationException(
                        $"Invalid destination table name: {destination}");

                return parts[1];
            }

            return destination;
        }

        private string Quote(string identifier)
        {
            if (string.IsNullOrWhiteSpace(identifier))
                throw new InvalidOperationException(
                    "SQL identifier cannot be empty.");

            return "[" + identifier.Replace("]", "]]") + "]";
        }

        private string ConstraintName(
            string prefix,
            string table,
            string suffix)
        {
            string name = $"{prefix}_{table}_{suffix}";

            if (name.Length > 128)
                name = name.Substring(0, 128);

            return name;
        }
    }
}

```

## **4. Example configuration**

For example, suppose your SQLite `DataSet` contains these tables:

- `TestRun`
- `TestRunProperty`
- `SUT`

Your configuration can define their SQL Server relationships like this:

```
var config = new AggregatorConfig();

config.Tables.Add(new TableDefinition
{
    Name = "TestRun",
    SourceTable = "TestRun",
    DestinationTable = "TestRun",
    Schema = "dbo",

    PrimaryKey = new List<string> { "TestRunID" },
    Identity = true,

    UniqueKeys = new List<UniqueKeyDefinition>
    {
        new UniqueKeyDefinition
        {
            Columns = new List<string> { "TestRunName" }
        }
    },

    Columns = new List<ColumnMapping>
    {
        new ColumnMapping
        {
            Source = "TestRunID",
            Destination = "TestRunID",
            SqlType = "INT"
        },
        new ColumnMapping
        {
            Source = "TestRunName",
            Destination = "TestRunName",
            SqlType = "NVARCHAR(200)"
        },
        new ColumnMapping
        {
            Source = "StartDate",
            Destination = "StartDate",
            SqlType = "DATETIME2"
        }
    }
});

config.Tables.Add(new TableDefinition
{
    Name = "TestRunProperty",
    SourceTable = "TestRunProperty",
    DestinationTable = "TestRunProperty",
    Schema = "dbo",

    PrimaryKey = new List<string> { "PropertyID" },
    Identity = true,

    Parent = "TestRun",

    JoinConditions = new List<JoinCondition>
    {
        new JoinCondition
        {
            ParentColumn = "TestRunID",
            ChildColumn = "TestRunID"
        }
    },

    UniqueKeys = new List<UniqueKeyDefinition>
    {
        new UniqueKeyDefinition
        {
            Columns = new List<string>
            {
                "PropertyName",
                "TestRunID"
            }
        }
    }
});

config.Tables.Add(new TableDefinition
{
    Name = "SUT",
    SourceTable = "SUT",
    DestinationTable = "SUT",
    Schema = "dbo",

    PrimaryKey = new List<string> { "SUTID" },
    Identity = true,

    // No parent or foreign key.
});
```

The example explicitly overrides the types of `TestRun` columns. For `TestRunProperty` and `SUT`, the code automatically determines types from their `DataTable` columns.

**One important detail:** The example assumes `TestRunProperty.TestRunID` and `TestRun.TestRunID` both resolve to `INT`. The child foreign key must use the same SQL type as the referenced parent column.

## **5. Calling the table creator**

Once your SQLite tables have already been loaded into a `DataSet`, call:

```
using System.Data;
using DataAggregator;

string connectionString =
    @"Server=YOUR_SERVER;Database=YOUR_DATABASE;Trusted_Connection=True;TrustServerCertificate=True;";

DataSet sourceData = GetYourExistingSQLiteDataSet();

var creator = new SqlServerTableCreator(connectionString);

creator.CreateTables(config, sourceData);
```

`GetYourExistingSQLiteDataSet()` represents your existing SQLite-loading code. You do not need to read SQLite again in the table creator.

## **6. Two small additions to make it fully usable**

**Create the destination schema if it does not exist.**

Inside `CreateTable()`, immediately before the `OBJECT_ID` check, add:

```
using (var schemaCommand = new SqlCommand(
    "IF SCHEMA_ID(@schema) IS NULL " +
    "EXEC(N'CREATE SCHEMA ' + QUOTENAME(@schema));",
    connection,
    transaction))
{
    schemaCommand.Parameters.AddWithValue(
        "@schema", schema);

    schemaCommand.ExecuteNonQuery();
}
```

This allows the creator to work with schemas other than `dbo` as well.

**Install the SQL Server client package** if it is not already in your project:

```
Install-Package Microsoft.Data.SqlClient
```

Or, if your existing application uses `System.Data.SqlClient`, replace the `using Microsoft.Data.SqlClient;` statement with `using System.Data.SqlClient;`.

## **7. Expected SQL Server result**

For the example configuration, the generated database structure will conceptually look like this:

```
CREATE TABLE dbo.TestRun
(
    TestRunID INT IDENTITY(1,1) NOT NULL,
    TestRunName NVARCHAR(200) NOT NULL,
    StartDate DATETIME2 NULL,

    CONSTRAINT PK_TestRun_1
        PRIMARY KEY (TestRunID),

    CONSTRAINT UQ_TestRun_1
        UNIQUE (TestRunName)
);

CREATE TABLE dbo.TestRunProperty
(
    PropertyID INT IDENTITY(1,1) NOT NULL,
    TestRunID INT NOT NULL,
    PropertyName NVARCHAR(MAX) NULL,

    CONSTRAINT PK_TestRunProperty_1
        PRIMARY KEY (PropertyID),

    CONSTRAINT UQ_TestRunProperty_1
        UNIQUE (PropertyName, TestRunID),

    CONSTRAINT FK_TestRunProperty_TestRun
        FOREIGN KEY (TestRunID)
        REFERENCES dbo.TestRun(TestRunID)
);

CREATE TABLE dbo.SUT
(
    SUTID INT IDENTITY(1,1) NOT NULL

    -- Other columns are generated from its DataTable.
);
```

The actual generated column definitions depend on the columns in your `DataTable` and any configured `SqlType` overrides.

## **Important design consideration**

This implementation creates the database structure only. It does not insert the SQLite records.

Also, because the example uses SQL Server-generated identity values, the later data-import stage must maintain a mapping between the original SQLite IDs and the newly generated SQL Server IDs. Otherwise, child records could reference the wrong parent records.

The overall workflow should be:

1. Load SQLite tables into your existing `DataSet`.
2. Create SQL Server tables and constraints using this implementation.
3. Import parent records and capture generated identity mappings.
4. Import child records, translating their foreign keys using those mappings.

This keeps table creation separate from data importing, which is the cleaner architecture for your `DataAggregator` application.
