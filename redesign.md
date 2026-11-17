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
