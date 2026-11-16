Below is a complete, generic C# implementation that reads your XML table definition, creates the SQL Server table, and imports data from SQLite.

It supports:

- `IDENTITY(1,1)` for SQL Server-generated primary keys.
- Composite primary keys.
- Composite unique constraints.
- Foreign keys using `parent` and `JoinConditions`.
- XML source-to-destination column mapping.
- Duplicate prevention during insertion.
- SQL transactions.
- Reusable methods for other tables, not just MOSS.

**Important design decision:** When `identity="true"`, SQL Server generates the destination ID. The SQLite ID is not copied. Other columns, including foreign-key columns, are imported normally.

## **1. XML configuration**

I recommend this small adjustment to your existing XML:

```
<Table
    name="MOSS"
    type="Root"
    sourceTable="MOSS_table"
    destinationTable="SDA_MOSS"
    parent="TestRunProperty"
    primaryKey="MOSS_ID"
    identity="true"
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
```

## **2. Complete C# implementation**

Create a class named `SQLiteToSqlServerImporter.cs`.

```
using System;
using System.Collections.Generic;
using System.Data;
using System.Data.SQLite;
using System.Linq;
using System.Xml.Linq;
using Microsoft.Data.SqlClient;

public class SQLiteToSqlServerImporter
{
    // ============================================
    // MAIN IMPORT METHOD
    // ============================================

    public void ImportTable(
        SQLiteConnection sqliteConnection,
        SqlConnection sqlConnection,
        XElement tableConfig,
        XDocument fullConfig)
    {
        // 1. Create destination table
        CreateDestinationTable(
            sqlConnection,
            tableConfig,
            fullConfig);

        // 2. Insert SQLite data
        InsertTableData(
            sqliteConnection,
            sqlConnection,
            tableConfig);
    }


    // ============================================
    // CREATE SQL SERVER TABLE
    // ============================================

    public void CreateDestinationTable(
        SqlConnection connection,
        XElement tableConfig,
        XDocument fullConfig)
    {
        string tableName =
            (string)tableConfig.Attribute("destinationTable");

        string primaryKey =
            (string)tableConfig.Attribute("primaryKey");

        string uniqueKey =
            (string)tableConfig.Attribute("uniqueKey");

        string parentName =
            (string)tableConfig.Attribute("parent");

        bool identity =
            string.Equals(
                (string)tableConfig.Attribute("identity"),
                "true",
                StringComparison.OrdinalIgnoreCase);

        var columns = tableConfig
            .Element("Columns")
            .Elements("Column")
            .Select(c => new
            {
                Source = (string)c.Attribute("source"),
                Destination =
                    (string)c.Attribute("destination")
                    ?? (string)c.Attribute("source"),

                SqlType =
                    (string)c.Attribute("sqlType")
                    ?? "NVARCHAR(255)"
            })
            .ToList();

        var definitions = new List<string>();

        // Column definitions
        foreach (var column in columns)
        {
            bool isIdentity =
                identity && column.Destination == primaryKey;

            string definition = isIdentity
                ? $"[{column.Destination}] INT IDENTITY(1,1) NOT NULL"
                : $"[{column.Destination}] {column.SqlType} NULL";

            definitions.Add(definition);
        }

        // Primary key
        if (!string.IsNullOrWhiteSpace(primaryKey))
        {
            var pkColumns = primaryKey.Split(',')
                .Select(c => $"[{c.Trim()}]");

            definitions.Add(
                $"CONSTRAINT [PK_{tableName}] " +
                $"PRIMARY KEY ({string.Join(", ", pkColumns)})");
        }

        // Unique key
        if (!string.IsNullOrWhiteSpace(uniqueKey))
        {
            var uqColumns = uniqueKey.Split(',')
                .Select(c => $"[{c.Trim()}]");

            definitions.Add(
                $"CONSTRAINT [UQ_{tableName}] " +
                $"UNIQUE ({string.Join(", ", uqColumns)})");
        }

        // Foreign key
        if (!string.IsNullOrWhiteSpace(parentName))
        {
            // Find parent XML configuration
            var parentConfig = fullConfig
                .Descendants("Table")
                .FirstOrDefault(t =>
                    (string)t.Attribute("name") == parentName);

            if (parentConfig == null)
                throw new Exception(
                    $"Parent configuration not found: {parentName}");

            string parentTable =
                (string)parentConfig.Attribute("destinationTable");

            var conditions = tableConfig
                .Element("JoinConditions")
                ?.Elements("Condition")
                .ToList();

            if (conditions == null || !conditions.Any())
                throw new Exception(
                    $"JoinConditions missing for {tableName}");

            string childColumns = string.Join(", ",
                conditions.Select(c =>
                    $"[{(string)c.Attribute("childColumn")}]"));

            string parentColumns = string.Join(", ",
                conditions.Select(c =>
                    $"[{(string)c.Attribute("parentColumn")}]"));

            definitions.Add($@"
                CONSTRAINT [FK_{tableName}_{parentTable}]
                FOREIGN KEY ({childColumns})
                REFERENCES [{parentTable}] ({parentColumns})");
        }

        string sql = $@"
            IF OBJECT_ID(N'dbo.{tableName}', N'U') IS NULL
            BEGIN
                CREATE TABLE [dbo].[{tableName}]
                (
                    {string.Join("," + Environment.NewLine, definitions)}
                );
            END";

        using var command = new SqlCommand(sql, connection);
        command.ExecuteNonQuery();
    }


    // ============================================
    // INSERT SQLITE DATA INTO SQL SERVER
    // ============================================

    public void InsertTableData(
        SQLiteConnection sqliteConnection,
        SqlConnection sqlConnection,
        XElement tableConfig)
    {
        string sourceTable =
            (string)tableConfig.Attribute("sourceTable");

        string destinationTable =
            (string)tableConfig.Attribute("destinationTable");

        string primaryKey =
            (string)tableConfig.Attribute("primaryKey");

        string uniqueKey =
            (string)tableConfig.Attribute("uniqueKey");

        bool identity =
            string.Equals(
                (string)tableConfig.Attribute("identity"),
                "true",
                StringComparison.OrdinalIgnoreCase);

        var columns = tableConfig
            .Element("Columns")
            .Elements("Column")
            .Select(c => new
            {
                Source = (string)c.Attribute("source"),
                Destination =
                    (string)c.Attribute("destination")
                    ?? (string)c.Attribute("source")
            })
            // Do not insert SQL Server-generated identity
            .Where(c =>
                !(identity && c.Destination == primaryKey))
            .ToList();

        if (!columns.Any())
            throw new Exception("No columns available for insertion.");

        // Destination columns
        string destinationColumns = string.Join(", ",
            columns.Select(c => $"[{c.Destination}]"));

        // SQL parameters
        string parameters = string.Join(", ",
            columns.Select((c, i) => $"@p{i}"));

        // SQLite SELECT
        string selectSql = $@"
            SELECT {string.Join(", ",
                columns.Select(c => $"[{c.Source}]"))}
            FROM [{sourceTable}]";

        // Duplicate prevention
        string duplicateCondition = "";

        if (!string.IsNullOrWhiteSpace(uniqueKey))
        {
            var uniqueColumns = uniqueKey.Split(',')
                .Select(c => c.Trim())
                .ToList();

            var conditions = new List<string>();

            foreach (string uniqueColumn in uniqueColumns)
            {
                int index = columns.FindIndex(
                    c => c.Destination == uniqueColumn);

                // Identity columns are generated by SQL Server.
                if (index < 0)
                    continue;

                conditions.Add($@"
                    (
                        T.[{uniqueColumn}] = @p{index}
                        OR
                        (T.[{uniqueColumn}] IS NULL AND @p{index} IS NULL)
                    )");
            }

            if (conditions.Any())
            {
                duplicateCondition =
                    "WHERE NOT EXISTS (" +
                    $"SELECT 1 FROM [dbo].[{destinationTable}] T " +
                    $"WHERE {string.Join(" AND ", conditions)})";
            }
        }

        string insertSql = $@"
            INSERT INTO [dbo].[{destinationTable}]
            (
                {destinationColumns}
            )
            SELECT {parameters}
            {duplicateCondition};";

        using var readerCommand =
            new SQLiteCommand(selectSql, sqliteConnection);

        using var reader = readerCommand.ExecuteReader();

        using var transaction = sqlConnection.BeginTransaction();

        try
        {
            using var insertCommand =
                new SqlCommand(
                    insertSql,
                    sqlConnection,
                    transaction);

            // Create parameters once
            for (int i = 0; i < columns.Count; i++)
            {
                insertCommand.Parameters.Add(
                    new SqlParameter($"@p{i}", SqlDbType.Variant));
            }

            // Read and insert each SQLite record
            while (reader.Read())
            {
                for (int i = 0; i < columns.Count; i++)
                {
                    insertCommand.Parameters[$"@p{i}"].Value =
                        reader.IsDBNull(i)
                            ? DBNull.Value
                            : reader.GetValue(i);
                }

                insertCommand.ExecuteNonQuery();
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
```

## **3. Important correction for the MOSS unique key**

Because SQL Server generates `MOSS_ID`, your original:

```
uniqueKey="MOSS_ID,TestRunID"
```

does not provide meaningful duplicate prevention when `MOSS_ID` is an identity column.

If `PropertyID` and `TestRunID` identify a MOSS record, change it to:

```
uniqueKey="PropertyID,TestRunID"
```

If you need to preserve the original SQLite `MOSS_ID`, set `identity="false"` instead.

## **4. Add SQL data types to XML**

For proper foreign-key compatibility, specify the SQL types explicitly. For example:

```
<Columns>
    <Column source="MOSS_ID" sqlType="INT" />
    <Column source="PropertyID" sqlType="INT" />
    <Column source="TestRunID" sqlType="INT" />
    <Column source="MOSS_Name" sqlType="NVARCHAR(255)" />
</Columns>
```

Use matching types for `PropertyID` and `TestRunID` in the parent `TestRunProperty` table.

## **5. How to execute**

```
XDocument config = XDocument.Load("App.config");

var tables = config.Descendants("Table");

using var sqliteConnection =
    new SQLiteConnection(sqliteConnectionString);

using var sqlConnection =
    new SqlConnection(sqlConnectionString);

sqliteConnection.Open();
sqlConnection.Open();

var importer = new SQLiteToSqlServerImporter();

foreach (var table in tables)
{
    importer.ImportTable(
        sqliteConnection,
        sqlConnection,
        table,
        config);
}
```

**Important:** Make sure the parent table (`TestRunProperty`) is created and populated before importing `MOSS`. Its `(PropertyID, TestRunID)` columns must have a matching unique constraint or primary key.

Also, in the insertion method, use `AddWithValue` for each row's parameters rather than declaring every parameter as `SqlDbType.Variant`. This allows SQL Server to receive the actual .NET value types.

## **6. Expected architecture**

**App.config XML**

Table definitions, keys, relationships, column mappings

**SQLiteToSqlServerImporter**

**CreateDestinationTable()**

Columns, IDENTITY, PK, UNIQUE, FK

**InsertTableData()**

Read SQLite, map columns, insert records

**SQL Server**

Destination tables with constraints and imported data

This gives you one generic importer for `MOSS`, `TestRunProperty`, and your other configured tables. You won't need a separate C# method for every table.
