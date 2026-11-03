Below is a complete implementation of the four C# files and the XML configuration, based on your clarified design.

I am making one important design decision: the code supports multiple RootTables under one TestRunTable, and multiple ChildTables under each RootTable. This makes the configuration flexible without requiring changes to the engine.

## 1. How the transfer will work

The selected SQLite `.db` file supplies all source tables, columns, and records. The XML configuration tells the application how to use them.

The transfer has two operations:

1. Transfer each configured TestRun table into its own SQL Server destination table.
2. For each RootTable associated with that TestRun, join the TestRun table to the RootTable and its ChildTables, then transfer the result into the RootTable's destination table.

For example:

```
SQLite .db
│
├── TestRunProperty
│   │
│   ├── Student
│   │   ├── StudentDetails
│   │   ├── CompetitionResults
│   │   │   └── Competition
│   │
│   └── Teacher
│       └── TeacherDetails
│
└── Other SQLite tables...
```

SQL Server destinations:

```
TestRunProperty  → TestRunProperty
Student          → StudentReport
Teacher          → TeacherReport
```

The TestRun table is imported independently, then used as the parent when querying its RootTables.

Important: This implementation uses the existing database technologies (`System.Data.SQLite` and `System.Data.SqlClient`) directly because I don't have the method signatures of your existing database classes. You can replace the connection and bulk-insert calls with your existing classes without changing the configuration model or query-building logic.

## 2. App.config.xml

I have retained your `TestRunTables`, `RootTables`, `ChildTables`, and `CommonHeaders` structure. I have added two things:

- `sourceTable` and `destination` information for each TestRun.
- `parent` and `joinCondition` information for each RootTable.

I have also added optional `destinationColumns` attributes. If omitted, the source column names are used as destination column names.

```
<?xml version="1.0" encoding="utf-8"?>

<configuration>

  <appSettings>
    <add key="BatchSize" value="1000" />
    <add key="CommandTimeout" value="300" />
    <add key="AnalysisServer" value="MSSQLServerName" />
  </appSettings>

  <!-- Common headers added to every transferred record -->
  <CommonHeaders
      value="SourceSystem,ImportedBy,ImportDate"
      headerValues="SQLite,DataTransferApp,{UTCNOW}" />

  <!-- ====================================== -->
  <!-- TEST RUN TABLES                        -->
  <!-- ====================================== -->

  <TestRunTables>

    <TestRunTable1>

      <add key="TestRunPropertyTableName"
           value="TestRunProperty" />

      <add key="TestRunPropertyDestinationTableName"
           value="TestRunProperty" />

      <add key="TestRunPropertyTestDateColumnName"
           value="TestDate" />

      <add key="TestRunPropertyTestLineColumnName"
           value="TestLine" />

      <add key="TestRunPropertyColumns"
           value="TestRunID,TestDate,TestLine" />

      <!-- TestRun source columns can map to destination columns -->
      <add key="TestRunPropertyDestinationColumns"
           value="TestRunID,TestDate,TestLine" />

    </TestRunTable1>

    <TestRunTable2>

      <add key="TestRunPropertyTableName"
           value="AnotherTestRunProperty" />

      <add key="TestRunPropertyDestinationTableName"
           value="AnotherTestRunProperty" />

      <add key="TestRunPropertyTestDateColumnName"
           value="TestDate" />

      <add key="TestRunPropertyTestLineColumnName"
           value="TestLine" />

      <add key="TestRunPropertyColumns"
           value="TestRunID,TestDate,TestLine" />

      <add key="TestRunPropertyDestinationColumns"
           value="TestRunID,TestDate,TestLine" />

    </TestRunTable2>

  </TestRunTables>

  <!-- ====================================== -->
  <!-- ROOT TABLES                            -->
  <!-- ====================================== -->

  <RootTables>

    <add key="Student"
         parent="TestRunTable1"
         destination="StudentReport"
         alias="s"
         joinType="INNER"
         joinCondition="tr.TestRunID=s.TestRunID"
         value="StudentID,FirstName,LastName" />

    <add key="Teacher"
         parent="TestRunTable1"
         destination="TeacherReport"
         alias="t"
         joinType="INNER"
         joinCondition="tr.TestRunID=t.TestRunID"
         value="TeacherID,Name,Email" />

  </RootTables>

  <!-- ====================================== -->
  <!-- CHILD TABLES                           -->
  <!-- ====================================== -->

  <ChildTables>

    <add key="StudentDetails"
         root="Student"
         alias="sd"
         joinType="LEFT"
         joinCondition="s.StudentID=sd.StudentID"
         value="Email,Phone,Address" />

    <add key="CompetitionResults"
         root="Student"
         alias="cr"
         joinType="LEFT"
         joinCondition="s.StudentID=cr.StudentID"
         value="CompetitionID,Score,Rank" />

    <add key="Competition"
         root="Student"
         alias="c"
         joinType="LEFT"
         joinCondition="cr.CompetitionID=c.CompetitionID"
         value="CompetitionName,CompetitionDate" />

  </ChildTables>

</configuration>
```

The table and column names above are examples. Replace them with the actual names in your SQLite database.

## 3. TransferConfig.cs

This file contains all configuration models.

```
using System.Collections.Generic;

namespace SQLiteToSqlServer.Configuration
{
    public class TransferConfig
    {
        public int BatchSize { get; set; } = 1000;

        public int CommandTimeout { get; set; } = 300;

        public string AnalysisServer { get; set; }

        public List<TestRunTableConfig> TestRunTables { get; set; }
            = new List<TestRunTableConfig>();

        public List<RootTableConfig> RootTables { get; set; }
            = new List<RootTableConfig>();

        public List<ChildTableConfig> ChildTables { get; set; }
            = new List<ChildTableConfig>();

        public List<CommonHeaderConfig> CommonHeaders { get; set; }
            = new List<CommonHeaderConfig>();
    }

    public class TestRunTableConfig
    {
        public string Name { get; set; }

        public string SourceTable { get; set; }

        public string Destination { get; set; }

        public string TestDateColumn { get; set; }

        public string TestLineColumn { get; set; }

        public List<string> Columns { get; set; }
            = new List<string>();

        public List<string> DestinationColumns { get; set; }
            = new List<string>();
    }

    public class RootTableConfig
    {
        public string Name { get; set; }

        public string Parent { get; set; }

        public string Destination { get; set; }

        public string Alias { get; set; }

        public string JoinType { get; set; }

        public string JoinCondition { get; set; }

        public List<string> Columns { get; set; }
            = new List<string>();

        public List<string> DestinationColumns { get; set; }
            = new List<string>();
    }

    public class ChildTableConfig
    {
        public string Name { get; set; }

        public string Root { get; set; }

        public string Alias { get; set; }

        public string JoinType { get; set; }

        public string JoinCondition { get; set; }

        public List<string> Columns { get; set; }
            = new List<string>();

        public List<string> DestinationColumns { get; set; }
            = new List<string>();
    }

    public class CommonHeaderConfig
    {
        public string Name { get; set; }

        public string Value { get; set; }
    }
}
```

## 4. ConfigLoader.cs

This reads the XML file and creates the configuration objects.

It supports:

- Any number of TestRunTable elements.
- Multiple RootTables under a TestRunTable.
- Multiple ChildTables under a RootTable.
- Comma-separated source and destination columns.
- Common headers.
- Optional destination column mappings.

```
using System;
using System.Collections.Generic;
using System.Linq;
using System.Xml.Linq;
using SQLiteToSqlServer.Configuration;

namespace SQLiteToSqlServer.Configuration
{
    public static class ConfigLoader
    {
        public static TransferConfig Load(string configPath)
        {
            if (string.IsNullOrWhiteSpace(configPath))
                throw new ArgumentException("Configuration path is required.");

            XDocument document = XDocument.Load(configPath);

            XElement configuration = document.Root;

            if (configuration == null ||
                configuration.Name != "configuration")
            {
                throw new Exception("Invalid configuration XML.");
            }

            var config = new TransferConfig();

            LoadAppSettings(configuration, config);
            LoadCommonHeaders(configuration, config);
            LoadTestRunTables(configuration, config);
            LoadRootTables(configuration, config);
            LoadChildTables(configuration, config);

            Validate(config);

            return config;
        }

        private static void LoadAppSettings(
            XElement configuration,
            TransferConfig config)
        {
            XElement settings = configuration.Element("appSettings");

            if (settings == null)
                return;

            config.BatchSize = GetIntSetting(
                settings, "BatchSize", 1000);

            config.CommandTimeout = GetIntSetting(
                settings, "CommandTimeout", 300);

            config.AnalysisServer = GetSetting(
                settings, "AnalysisServer");
        }

        private static void LoadCommonHeaders(
            XElement configuration,
            TransferConfig config)
        {
            XElement headers =
                configuration.Element("CommonHeaders");

            if (headers == null)
                return;

            List<string> names =
                SplitColumns((string)headers.Attribute("value"));

            List<string> values =
                SplitColumns((string)headers.Attribute("headerValues"));

            if (names.Count != values.Count)
            {
                throw new Exception(
                    "CommonHeaders value and headerValues counts do not match.");
            }

            for (int i = 0; i < names.Count; i++)
            {
                config.CommonHeaders.Add(
                    new CommonHeaderConfig
                    {
                        Name = names[i],
                        Value = values[i]
                    });
            }
        }

        private static void LoadTestRunTables(
            XElement configuration,
            TransferConfig config)
        {
            XElement testRuns =
                configuration.Element("TestRunTables");

            if (testRuns == null)
                return;

            foreach (XElement testRun in testRuns.Elements())
            {
                string name = testRun.Name.LocalName;

                string sourceTable = GetNestedSetting(
                    testRun, "TestRunPropertyTableName");

                string destination = GetNestedSetting(
                    testRun, "TestRunPropertyDestinationTableName");

                string dateColumn = GetNestedSetting(
                    testRun, "TestRunPropertyTestDateColumnName");

                string lineColumn = GetNestedSetting(
                    testRun, "TestRunPropertyTestLineColumnName");

                List<string> columns = SplitColumns(
                    GetNestedSetting(testRun, "TestRunPropertyColumns"));

                List<string> destinationColumns = SplitColumns(
                    GetNestedSetting(
                        testRun,
                        "TestRunPropertyDestinationColumns"));

                if (destinationColumns.Count == 0)
                    destinationColumns = new List<string>(columns);

                config.TestRunTables.Add(
                    new TestRunTableConfig
                    {
                        Name = name,
                        SourceTable = sourceTable,
                        Destination = destination,
                        TestDateColumn = dateColumn,
                        TestLineColumn = lineColumn,
                        Columns = columns,
                        DestinationColumns = destinationColumns
                    });
            }
        }

        private static void LoadRootTables(
            XElement configuration,
            TransferConfig config)
        {
            XElement roots = configuration.Element("RootTables");

            if (roots == null)
                return;

            foreach (XElement element in roots.Elements("add"))
            {
                List<string> columns =
                    SplitColumns((string)element.Attribute("value"));

                List<string> destinationColumns =
                    SplitColumns(
                        (string)element.Attribute("destinationColumns"));

                if (destinationColumns.Count == 0)
                    destinationColumns = new List<string>(columns);

                config.RootTables.Add(
                    new RootTableConfig
                    {
                        Name = (string)element.Attribute("key"),
                        Parent = (string)element.Attribute("parent"),
                        Destination = (string)element.Attribute("destination"),
                        Alias = (string)element.Attribute("alias"),
                        JoinType = (string)element.Attribute("joinType"),
                        JoinCondition =
                            (string)element.Attribute("joinCondition"),
                        Columns = columns,
                        DestinationColumns = destinationColumns
                    });
            }
        }

        private static void LoadChildTables(
            XElement configuration,
            TransferConfig config)
        {
            XElement children =
                configuration.Element("ChildTables");

            if (children == null)
                return;

            foreach (XElement element in children.Elements("add"))
            {
                List<string> columns =
                    SplitColumns((string)element.Attribute("value"));

                List<string> destinationColumns =
                    SplitColumns(
                        (string)element.Attribute("destinationColumns"));

                if (destinationColumns.Count == 0)
                    destinationColumns = new List<string>(columns);

                config.ChildTables.Add(
                    new ChildTableConfig
                    {
                        Name = (string)element.Attribute("key"),
                        Root = (string)element.Attribute("root"),
                        Alias = (string)element.Attribute("alias"),
                        JoinType = (string)element.Attribute("joinType"),
                        JoinCondition =
                            (string)element.Attribute("joinCondition"),
                        Columns = columns,
                        DestinationColumns = destinationColumns
                    });
            }
        }

        private static void Validate(TransferConfig config)
        {
            if (config.BatchSize <= 0)
                throw new Exception("BatchSize must be greater than zero.");

            if (config.CommandTimeout <= 0)
                throw new Exception(
                    "CommandTimeout must be greater than zero.");

            if (config.TestRunTables.Count == 0)
                throw new Exception("No TestRunTables configured.");

            foreach (var testRun in config.TestRunTables)
            {
                if (string.IsNullOrWhiteSpace(testRun.SourceTable))
                    throw new Exception(
                        "Source table missing in " + testRun.Name);

                if (string.IsNullOrWhiteSpace(testRun.Destination))
                    throw new Exception(
                        "Destination missing in " + testRun.Name);

                ValidateColumnMappings(
                    testRun.Columns,
                    testRun.DestinationColumns,
                    testRun.Name);
            }

            foreach (var root in config.RootTables)
            {
                if (string.IsNullOrWhiteSpace(root.Name) ||
                    string.IsNullOrWhiteSpace(root.Parent) ||
                    string.IsNullOrWhiteSpace(root.Destination) ||
                    string.IsNullOrWhiteSpace(root.Alias) ||
                    string.IsNullOrWhiteSpace(root.JoinCondition))
                {
                    throw new Exception(
                        "Incomplete RootTable configuration: " + root.Name);
                }

                ValidateColumnMappings(
                    root.Columns,
                    root.DestinationColumns,
                    root.Name);

                bool parentExists = config.TestRunTables.Any(
                    x => string.Equals(
                        x.Name, root.Parent,
                        StringComparison.OrdinalIgnoreCase));

                if (!parentExists)
                    throw new Exception(
                        "TestRun parent not found for root: " + root.Name);
            }

            foreach (var child in config.ChildTables)
            {
                if (string.IsNullOrWhiteSpace(child.Name) ||
                    string.IsNullOrWhiteSpace(child.Root) ||
                    string.IsNullOrWhiteSpace(child.Alias) ||
                    string.IsNullOrWhiteSpace(child.JoinCondition))
                {
                    throw new Exception(
                        "Incomplete ChildTable configuration: " +
                        child.Name);
                }

                ValidateColumnMappings(
                    child.Columns,
                    child.DestinationColumns,
                    child.Name);

                bool rootExists = config.RootTables.Any(
                    x => string.Equals(
                        x.Name, child.Root,
                        StringComparison.OrdinalIgnoreCase));

                if (!rootExists)
                    throw new Exception(
                        "Root not found for child: " + child.Name);
            }

            ValidateUniqueNames(config);
        }

        private static void ValidateColumnMappings(
            List<string> source,
            List<string> destination,
            string tableName)
        {
            if (source == null || source.Count == 0)
                throw new Exception(
                    "No source columns configured for " + tableName);

            if (destination == null ||
                source.Count != destination.Count)
            {
                throw new Exception(
                    "Source and destination column counts do not match for " +
                    tableName);
            }
        }

        private static void ValidateUniqueNames(TransferConfig config)
        {
            var testRunNames = new HashSet<string>(
                StringComparer.OrdinalIgnoreCase);

            foreach (var item in config.TestRunTables)
            {
                if (!testRunNames.Add(item.Name))
                    throw new Exception(
                        "Duplicate TestRun configuration: " + item.Name);
            }

            var rootNames = new HashSet<string>(
                StringComparer.OrdinalIgnoreCase);

            foreach (var item in config.RootTables)
            {
                if (!rootNames.Add(item.Name))
                    throw new Exception(
                        "Duplicate RootTable configuration: " + item.Name);
            }

            var childNames = new HashSet<string>(
                StringComparer.OrdinalIgnoreCase);

            foreach (var item in config.ChildTables)
            {
                if (!childNames.Add(item.Name))
                    throw new Exception(
                        "Duplicate ChildTable configuration: " + item.Name);
            }
        }

        private static string GetNestedSetting(
            XElement parent,
            string key)
        {
            XElement element = parent.Elements("add")
                .FirstOrDefault(x =>
                    string.Equals(
                        (string)x.Attribute("key"),
                        key,
                        StringComparison.OrdinalIgnoreCase));

            return element == null
                ? null
                : (string)element.Attribute("value");
        }

        private static string GetSetting(
            XElement settings,
            string key)
        {
            XElement element = settings.Elements("add")
                .FirstOrDefault(x =>
                    string.Equals(
                        (string)x.Attribute("key"),
                        key,
                        StringComparison.OrdinalIgnoreCase));

            return element == null
                ? null
                : (string)element.Attribute("value");
        }

        private static int GetIntSetting(
            XElement settings,
            string key,
            int defaultValue)
        {
            string value = GetSetting(settings, key);

            int result;

            return int.TryParse(value, out result)
                ? result
                : defaultValue;
        }

        private static List<string> SplitColumns(string value)
        {
            if (string.IsNullOrWhiteSpace(value))
                return new List<string>();

            return value.Split(',')
                .Select(x => x.Trim())
                .Where(x => !string.IsNullOrWhiteSpace(x))
                .ToList();
        }
    }
}
```

## 5. QueryBuilder.cs

This is the part that understands your hierarchy.

It builds two types of queries:

- `BuildTestRunQuery()`: Reads the configured TestRun table for its independent SQL Server destination.
- `BuildRootQuery()`: Joins the TestRun table to its RootTable and all configured ChildTables.

It also validates that configured source tables and columns actually exist in the selected SQLite database.

Join conditions support equality comparisons connected by `AND`, such as:

```
tr.TestRunID=s.TestRunID
s.StudentID=cr.StudentID
cr.CompetitionID=c.CompetitionID
```

```
using System;
using System.Collections.Generic;
using System.Data.SQLite;
using System.Linq;
using System.Text.RegularExpressions;
using SQLiteToSqlServer.Configuration;

namespace SQLiteToSqlServer.Engine
{
    public class TransferQuery
    {
        public string Sql { get; set; }

        public List<OutputColumn> OutputColumns { get; set; }
            = new List<OutputColumn>();
    }

    public class OutputColumn
    {
        public string Alias { get; set; }

        public string DestinationColumn { get; set; }
    }

    public static class QueryBuilder
    {
        private static readonly Regex IdentifierRegex =
            new Regex(
                @"^[A-Za-z_][A-Za-z0-9_]*$",
                RegexOptions.Compiled);

        private static readonly Regex JoinPartRegex =
            new Regex(
                @"^\s*([A-Za-z_][A-Za-z0-9_]*)\.([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([A-Za-z_][A-Za-z0-9_]*)\.([A-Za-z_][A-Za-z0-9_]*)\s*$",
                RegexOptions.Compiled);

        public static TransferQuery BuildTestRunQuery(
            SQLiteConnection connection,
            TestRunTableConfig testRun)
        {
            ValidateTable(connection, testRun.SourceTable);

            ValidateColumns(
                connection,
                testRun.SourceTable,
                testRun.Columns);

            var query = new TransferQuery();

            var selectColumns = new List<string>();

            for (int i = 0; i < testRun.Columns.Count; i++)
            {
                string sourceColumn = testRun.Columns[i];
                string destinationColumn =
                    testRun.DestinationColumns[i];

                string alias = "col" + i;

                selectColumns.Add(
                    QuoteIdentifier(sourceColumn) +
                    " AS " + QuoteIdentifier(alias));

                query.OutputColumns.Add(
                    new OutputColumn
                    {
                        Alias = alias,
                        DestinationColumn = destinationColumn
                    });
            }

            query.Sql =
                "SELECT " +
                string.Join(", ", selectColumns) +
                " FROM " +
                QuoteIdentifier(testRun.SourceTable);

            return query;
        }

        public static TransferQuery BuildRootQuery(
            SQLiteConnection connection,
            TestRunTableConfig testRun,
            RootTableConfig root,
            List<ChildTableConfig> children)
        {
            ValidateTable(connection, testRun.SourceTable);
            ValidateTable(connection, root.Name);

            ValidateColumns(
                connection,
                root.Name,
                root.Columns);

            ValidateColumns(
                connection,
                testRun.SourceTable,
                GetColumnsUsedInJoin(testRun.Name, root.JoinCondition));

            ValidateColumns(
                connection,
                root.Name,
                GetColumnsUsedInJoin(root.Alias, root.JoinCondition));

            ValidateJoinType(root.JoinType);

            var aliases = new Dictionary<string, string>(
                StringComparer.OrdinalIgnoreCase);

            aliases.Add("tr", testRun.SourceTable);
            aliases.Add(root.Alias, root.Name);

            ValidateJoinCondition(
                connection,
                root.JoinCondition,
                aliases);

            var query = new TransferQuery();

            var selectColumns = new List<string>();

            int columnIndex = 0;

            // Root columns.
            AddSelectColumns(
                query,
                selectColumns,
                root.Alias,
                root.Columns,
                root.DestinationColumns,
                ref columnIndex);

            // Child columns and JOINs.
            var joinStatements = new List<string>();

            joinStatements.Add(
                GetJoinStatement(
                    root.JoinType,
                    root.Name,
                    root.Alias,
                    root.JoinCondition,
                    true));

            foreach (var child in children)
            {
                ValidateTable(connection, child.Name);

                ValidateColumns(
                    connection,
                    child.Name,
                    child.Columns);

                ValidateJoinType(child.JoinType);

                if (aliases.ContainsKey(child.Alias))
                {
                    throw new Exception(
                        "Duplicate SQL alias: " + child.Alias);
                }

                ValidateJoinCondition(
                    connection,
                    child.JoinCondition,
                    aliases);

                AddSelectColumns(
                    query,
                    selectColumns,
                    child.Alias,
                    child.Columns,
                    child.DestinationColumns,
                    ref columnIndex);

                joinStatements.Add(
                    GetJoinStatement(
                        child.JoinType,
                        child.Name,
                        child.Alias,
                        child.JoinCondition,
                        false));

                aliases.Add(child.Alias, child.Name);
            }

            if (selectColumns.Count == 0)
            {
                throw new Exception(
                    "No columns configured for root: " + root.Name);
            }

            string from =
                " FROM " +
                QuoteIdentifier(testRun.SourceTable) +
                " AS " + QuoteIdentifier("tr");

            string sql =
                "SELECT " +
                string.Join(", ", selectColumns) +
                from +
                " " +
                string.Join(" ", joinStatements);

            query.Sql = sql;

            return query;
        }

        private static void AddSelectColumns(
            TransferQuery query,
            List<string> selectColumns,
            string tableAlias,
            List<string> sourceColumns,
            List<string> destinationColumns,
            ref int columnIndex)
        {
            for (int i = 0; i < sourceColumns.Count; i++)
            {
                string alias = "col" + columnIndex++;

                string sourceColumn = sourceColumns[i];
                string destinationColumn = destinationColumns[i];

                selectColumns.Add(
                    QuoteIdentifier(tableAlias) +
                    "." +
                    QuoteIdentifier(sourceColumn) +
                    " AS " +
                    QuoteIdentifier(alias));

                query.OutputColumns.Add(
                    new OutputColumn
                    {
                        Alias = alias,
                        DestinationColumn = destinationColumn
                    });
            }
        }

        private static string GetJoinStatement(
            string joinType,
            string tableName,
            string alias,
            string joinCondition,
            bool rootJoin)
        {
            return
                joinType.ToUpperInvariant() +
                " JOIN " +
                QuoteIdentifier(tableName) +
                " AS " +
                QuoteIdentifier(alias) +
                " ON " +
                NormalizeJoinCondition(joinCondition);
        }

        private static void ValidateJoinCondition(
            SQLiteConnection connection,
            string condition,
            Dictionary<string, string> aliases)
        {
            if (string.IsNullOrWhiteSpace(condition))
                throw new Exception("Join condition is required.");

            string[] parts = Regex.Split(
                condition,
                @"\s+AND\s+",
                RegexOptions.IgnoreCase);

            foreach (string part in parts)
            {
                Match match = JoinPartRegex.Match(part);

                if (!match.Success)
                {
                    throw new Exception(
                        "Unsupported join condition: " + part +
                        ". Only alias.column = alias.column " +
                        "conditions connected by AND are supported.");
                }

                string leftAlias = match.Groups[1].Value;
                string leftColumn = match.Groups[2].Value;

                string rightAlias = match.Groups[3].Value;
                string rightColumn = match.Groups[4].Value;

                if (!aliases.ContainsKey(leftAlias))
                {
                    throw new Exception(
                        "Unknown join alias: " + leftAlias);
                }

                if (!aliases.ContainsKey(rightAlias))
                {
                    throw new Exception(
                        "Unknown join alias: " + rightAlias);
                }

                ValidateColumns(
                    connection,
                    aliases[leftAlias],
                    new List<string> { leftColumn });

                ValidateColumns(
                    connection,
                    aliases[rightAlias],
                    new List<string> { rightColumn });
            }
        }

        private static List<string> GetColumnsUsedInJoin(
            string alias,
            string condition)
        {
            var columns = new List<string>();

            string[] parts = Regex.Split(
                condition ?? "",
                @"\s+AND\s+",
                RegexOptions.IgnoreCase);

            foreach (string part in parts)
            {
                Match match = JoinPartRegex.Match(part);

                if (!match.Success)
                    continue;

                if (string.Equals(
                    match.Groups[1].Value,
                    alias,
                    StringComparison.OrdinalIgnoreCase))
                {
                    columns.Add(match.Groups[2].Value);
                }

                if (string.Equals(
                    match.Groups[3].Value,
                    alias,
                    StringComparison.OrdinalIgnoreCase))
                {
                    columns.Add(match.Groups[4].Value);
                }
            }

            return columns.Distinct(
                StringComparer.OrdinalIgnoreCase).ToList();
        }

        private static string NormalizeJoinCondition(string condition)
        {
            string[] parts = Regex.Split(
                condition,
                @"\s+AND\s+",
                RegexOptions.IgnoreCase);

            var normalized = new List<string>();

            foreach (string part in parts)
            {
                Match match = JoinPartRegex.Match(part);

                if (!match.Success)
                    throw new Exception(
                        "Invalid join condition: " + part);

                normalized.Add(
                    QuoteIdentifier(match.Groups[1].Value) +
                    "." +
                    QuoteIdentifier(match.Groups[2].Value) +
                    " = " +
                    QuoteIdentifier(match.Groups[3].Value) +
                    "." +
                    QuoteIdentifier(match.Groups[4].Value));
            }

            return string.Join(" AND ", normalized);
        }

        private static void ValidateJoinType(string joinType)
        {
            string type = (joinType ?? "").ToUpperInvariant();

            if (type != "INNER" &&
                type != "LEFT")
            {
                throw new Exception(
                    "Unsupported JOIN type: " + joinType +
                    ". Supported types are INNER and LEFT.");
            }
        }

        private static void ValidateTable(
            SQLiteConnection connection,
            string tableName)
        {
            ValidateIdentifier(tableName);

            const string sql = @"
                SELECT COUNT(*)
                FROM sqlite_master
                WHERE type = 'table'
                  AND name = @tableName;";

            using (var command =
                new SQLiteCommand(sql, connection))
            {
                command.Parameters.AddWithValue(
                    "@tableName", tableName);

                long count = Convert.ToInt64(
                    command.ExecuteScalar());

                if (count == 0)
                {
                    throw new Exception(
                        "SQLite table does not exist: " + tableName);
                }
            }
        }

        private static void ValidateColumns(
            SQLiteConnection connection,
            string tableName,
            List<string> requiredColumns)
        {
            if (requiredColumns == null)
                return;

            var actualColumns = new HashSet<string>(
                StringComparer.OrdinalIgnoreCase);

            string sql =
                "PRAGMA table_info(" +
                QuoteIdentifier(tableName) +
                ");";

            using (var command =
                new SQLiteCommand(sql, connection))
            using (var reader = command.ExecuteReader())
            {
                while (reader.Read())
                {
                    actualColumns.Add(
                        Convert.ToString(reader["name"]));
                }
            }

            foreach (string column in requiredColumns)
            {
                ValidateIdentifier(column);

                if (!actualColumns.Contains(column))
                {
                    throw new Exception(
                        "Column '" + column +
                        "' does not exist in SQLite table '" +
                        tableName + "'.");
                }
            }
        }

        public static string QuoteIdentifier(string identifier)
        {
            ValidateIdentifier(identifier);

            return "\"" + identifier + "\"";
        }

        private static void ValidateIdentifier(string identifier)
        {
            if (string.IsNullOrWhiteSpace(identifier) ||
                !IdentifierRegex.IsMatch(identifier))
            {
                throw new Exception(
                    "Invalid SQL identifier: " + identifier);
            }
        }
    }
}
```

A few details about this implementation:

- The TestRun table alias is `tr`.
- RootTable aliases are defined in `App.config.xml`.
- ChildTable aliases are defined in `App.config.xml`.
- A child can join to the root or to a previously configured child.
- The child configuration order matters. For example, `CompetitionResults` must appear before `Competition`.
- A root with no children works normally. It generates a query with only the TestRun-to-Root join.

## 6. DataTransferEngine.cs

This is the main execution engine.

It performs the following operations:

1. Opens the selected SQLite `.db` file in read-only mode.
2. Opens SQL Server.
3. Starts a SQL Server transaction.
4. Processes each TestRun table.
5. Transfers its configured columns to its SQL Server destination.
6. Finds all RootTables belonging to that TestRun.
7. Builds and executes a query for each RootTable and its children.
8. Transfers the results in batches.
9. Commits the transaction when everything succeeds.
10. Rolls back the transaction if an error occurs.

```
using System;
using System.Data;
using System.Data.SQLite;
using System.Data.SqlClient;
using System.IO;
using System.Linq;
using System.Collections.Generic;

using SQLiteToSqlServer.Configuration;

namespace SQLiteToSqlServer.Engine
{
    public class TransferResult
    {
        public bool Success { get; set; }

        public int ProcessedTestRunTables { get; set; }

        public int ProcessedRootTables { get; set; }

        public long TestRunRecordsInserted { get; set; }

        public long RootRecordsInserted { get; set; }

        public long TotalRecordsInserted
        {
            get
            {
                return TestRunRecordsInserted +
                       RootRecordsInserted;
            }
        }

        public string Message { get; set; }
    }

    public class DataTransferEngine
    {
        private readonly TransferConfig _config;
        private readonly string _sqliteFilePath;
        private readonly string _sqlServerConnectionString;

        public DataTransferEngine(
            TransferConfig config,
            string sqliteFilePath,
            string sqlServerConnectionString)
        {
            _config = config ??
                throw new ArgumentNullException("config");

            _sqliteFilePath = sqliteFilePath;

            _sqlServerConnectionString =
                sqlServerConnectionString;
        }

        public TransferResult Execute(
            Action<string> reportProgress = null)
        {
            var result = new TransferResult();

            if (string.IsNullOrWhiteSpace(_sqliteFilePath) ||
                !File.Exists(_sqliteFilePath))
            {
                throw new FileNotFoundException(
                    "SQLite database file was not found.",
                    _sqliteFilePath);
            }

            string sqliteConnectionString =
                new SQLiteConnectionStringBuilder
                {
                    DataSource = _sqliteFilePath,
                    ReadOnly = true,
                    FailIfMissing = true
                }.ToString();

            using (var sqliteConnection =
                new SQLiteConnection(sqliteConnectionString))
            using (var sqlConnection =
                new SqlConnection(_sqlServerConnectionString))
            {
                reportProgress?.Invoke(
                    "Opening SQLite database...");

                sqliteConnection.Open();

                reportProgress?.Invoke(
                    "Connecting to SQL Server...");

                sqlConnection.Open();

                using (var transaction =
                    sqlConnection.BeginTransaction())
                {
                    try
                    {
                        // Process each configured TestRun table.
                        foreach (var testRun in _config.TestRunTables)
                        {
                            reportProgress?.Invoke(
                                "Processing TestRun table: " +
                                testRun.SourceTable);

                            // 1. Transfer TestRun records independently.
                            TransferQuery testRunQuery =
                                QueryBuilder.BuildTestRunQuery(
                                    sqliteConnection,
                                    testRun);

                            long testRunCount = ProcessQuery(
                                sqliteConnection,
                                sqlConnection,
                                transaction,
                                testRunQuery,
                                testRun.Destination,
                                reportProgress);

                            result.TestRunRecordsInserted +=
                                testRunCount;

                            result.ProcessedTestRunTables++;

                            reportProgress?.Invoke(
                                testRun.SourceTable +
                                ": " + testRunCount +
                                " records transferred.");

                            // 2. Find roots belonging to this TestRun.
                            List<RootTableConfig> roots =
                                _config.RootTables
                                    .Where(x =>
                                        string.Equals(
                                            x.Parent,
                                            testRun.Name,
                                            StringComparison
                                                .OrdinalIgnoreCase))
                                    .ToList();

                            // 3. Process each root independently.
                            foreach (var root in roots)
                            {
                                reportProgress?.Invoke(
                                    "Processing RootTable: " +
                                    root.Name);

                                // Find children belonging to this root.
                                List<ChildTableConfig> children =
                                    _config.ChildTables
                                        .Where(x =>
                                            string.Equals(
                                                x.Root,
                                                root.Name,
                                                StringComparison
                                                    .OrdinalIgnoreCase))
                                        .ToList();

                                // Build TestRun -> Root -> Child query.
                                TransferQuery rootQuery =
                                    QueryBuilder.BuildRootQuery(
                                        sqliteConnection,
                                        testRun,
                                        root,
                                        children);

                                // Transfer root and child data.
                                long rootCount = ProcessQuery(
                                    sqliteConnection,
                                    sqlConnection,
                                    transaction,
                                    rootQuery,
                                    root.Destination,
                                    reportProgress);

                                result.RootRecordsInserted +=
                                    rootCount;

                                result.ProcessedRootTables++;

                                reportProgress?.Invoke(
                                    root.Name +
                                    ": " + rootCount +
                                    " records transferred.");
                            }
                        }

                        // All transfers succeeded.
                        transaction.Commit();

                        result.Success = true;

                        result.Message =
                            "Data transfer completed successfully.";

                        reportProgress?.Invoke(
                            result.Message);
                    }
                    catch
                    {
                        // Roll back all SQL Server inserts.
                        transaction.Rollback();

                        throw;
                    }
                }
            }

            return result;
        }

        private long ProcessQuery(
            SQLiteConnection sqliteConnection,
            SqlConnection sqlConnection,
            SqlTransaction transaction,
            TransferQuery query,
            string destinationTable,
            Action<string> reportProgress)
        {
            long insertedRecords = 0;

            using (var command =
                new SQLiteCommand(query.Sql, sqliteConnection))
            {
                command.CommandTimeout =
                    _config.CommandTimeout;

                using (var reader = command.ExecuteReader())
                {
                    DataTable batch =
                        CreateDataTable(query);

                    while (reader.Read())
                    {
                        DataRow row = batch.NewRow();

                        // Read mapped source columns.
                        foreach (var column in query.OutputColumns)
                        {
                            int ordinal =
                                reader.GetOrdinal(column.Alias);

                            row[column.DestinationColumn] =
                                reader.IsDBNull(ordinal)
                                    ? DBNull.Value
                                    : reader.GetValue(ordinal);
                        }

                        // Add common header columns.
                        AddCommonHeaders(row);

                        batch.Rows.Add(row);

                        // Transfer full batches.
                        if (batch.Rows.Count >= _config.BatchSize)
                        {
                            int currentBatchSize =
                                batch.Rows.Count;

                            WriteBatch(
                                sqlConnection,
                                transaction,
                                destinationTable,
                                batch);

                            insertedRecords +=
                                currentBatchSize;

                            batch.Clear();

                            reportProgress?.Invoke(
                                "Transferred " +
                                insertedRecords +
                                " records into " +
                                destinationTable);
                        }
                    }

                    // Transfer remaining records.
                    if (batch.Rows.Count > 0)
                    {
                        int remaining = batch.Rows.Count;

                        WriteBatch(
                            sqlConnection,
                            transaction,
                            destinationTable,
                            batch);

                        insertedRecords += remaining;

                        batch.Clear();
                    }
                }
            }

            return insertedRecords;
        }

        private DataTable CreateDataTable(TransferQuery query)
        {
            var table = new DataTable();

            foreach (var column in query.OutputColumns)
            {
                AddUniqueColumn(
                    table,
                    column.DestinationColumn);
            }

            foreach (var header in _config.CommonHeaders)
            {
                AddUniqueColumn(table, header.Name);
            }

            return table;
        }

        private void AddUniqueColumn(
            DataTable table,
            string columnName)
        {
            if (string.IsNullOrWhiteSpace(columnName))
            {
                throw new Exception(
                    "Destination column name cannot be empty.");
            }

            if (table.Columns.Contains(columnName))
            {
                throw new Exception(
                    "Duplicate destination column: " +
                    columnName +
                    ". Use destinationColumns in XML to resolve it.");
            }

            table.Columns.Add(
                columnName,
                typeof(object));
        }

        private void AddCommonHeaders(DataRow row)
        {
            foreach (var header in _config.CommonHeaders)
            {
                object value = header.Value;

                if (string.Equals(
                    Convert.ToString(value),
                    "{UTCNOW}",
                    StringComparison.OrdinalIgnoreCase))
                {
                    value = DateTime.UtcNow;
                }

                row[header.Name] =
                    value ?? DBNull.Value;
            }
        }

        private void WriteBatch(
            SqlConnection connection,
            SqlTransaction transaction,
            string destinationTable,
            DataTable batch)
        {
            using (var bulkCopy =
                new SqlBulkCopy(
                    connection,
                    SqlBulkCopyOptions.CheckConstraints,
                    transaction))
            {
                bulkCopy.DestinationTableName =
                    QuoteSqlServerTable(destinationTable);

                bulkCopy.BatchSize =
                    _config.BatchSize;

                bulkCopy.BulkCopyTimeout =
                    _config.CommandTimeout;

                foreach (DataColumn column in batch.Columns)
                {
                    bulkCopy.ColumnMappings.Add(
                        column.ColumnName,
                        column.ColumnName);
                }

                bulkCopy.WriteToServer(batch);
            }
        }

        private string QuoteSqlServerTable(string tableName)
        {
            if (string.IsNullOrWhiteSpace(tableName))
            {
                throw new Exception(
                    "SQL Server destination table is required.");
            }

            string[] parts = tableName.Split('.');

            if (parts.Length < 1 || parts.Length > 2)
            {
                throw new Exception(
                    "Destination must be TableName or Schema.TableName.");
            }

            var quotedParts = new List<string>();

            foreach (string part in parts)
            {
                string name = part.Trim();

                if (!System.Text.RegularExpressions.Regex.IsMatch(
                    name,
                    @"^[A-Za-z_][A-Za-z0-9_]*$"))
                {
                    throw new Exception(
                        "Invalid SQL Server table identifier: " + name);
                }

                quotedParts.Add("[" + name + "]");
            }

            return string.Join(".", quotedParts);
        }
    }
}
```

Important correction for `QueryBuilder.cs`: In `BuildRootQuery()`, the TestRun alias is `tr`, not the TestRun configuration element name. Therefore, use `"tr"` when validating the TestRun side of the root join:

Replace:

```
ValidateColumns(
    connection,
    testRun.SourceTable,
    GetColumnsUsedInJoin(testRun.Name, root.JoinCondition));
```

With:

```
ValidateColumns(
    connection,
    testRun.SourceTable,
    GetColumnsUsedInJoin("tr", root.JoinCondition));
```

This is necessary for the example `tr.TestRunID=s.TestRunID` to validate correctly.

## 7. How to call DataTransferEngine from your Windows Form

Your Browse button selects the SQLite file. Your Start Import button executes the engine.

```
using System;
using System.IO;
using System.Threading.Tasks;
using System.Windows.Forms;

using SQLiteToSqlServer.Configuration;
using SQLiteToSqlServer.Engine;

private async void btnStartImport_Click(
    object sender,
    EventArgs e)
{
    string sqliteFile = txtDatabasePath.Text;

    if (string.IsNullOrWhiteSpace(sqliteFile) ||
        !File.Exists(sqliteFile))
    {
        MessageBox.Show("Please select a valid SQLite database.");
        return;
    }

    btnStartImport.Enabled = false;

    try
    {
        string configPath = Path.Combine(
            Application.StartupPath,
            "App.config.xml");

        TransferConfig config =
            ConfigLoader.Load(configPath);

        // Use the connection string from your existing
        // SQLServerDatabase class.
        string sqlConnectionString =
            GetYourExistingSqlServerConnectionString();

        var engine = new DataTransferEngine(
            config,
            sqliteFile,
            sqlConnectionString);

        TransferResult result =
            await Task.Run(() =>
                engine.Execute(message =>
                {
                    if (!IsDisposed && IsHandleCreated)
                    {
                        BeginInvoke(new Action(() =>
                        {
                            lblStatus.Text = message;
                        }));
                    }
                }));

        MessageBox.Show(
            "Import completed successfully.\n\n" +
            "TestRun tables: " +
            result.ProcessedTestRunTables + "\n" +

            "Root tables: " +
            result.ProcessedRootTables + "\n" +

            "TestRun records: " +
            result.TestRunRecordsInserted + "\n" +

            "Root records: " +
            result.RootRecordsInserted + "\n\n" +

            "Total records: " +
            result.TotalRecordsInserted);
    }
    catch (Exception ex)
    {
        MessageBox.Show(
            "Import failed:\n" + ex.Message);
    }
    finally
    {
        btnStartImport.Enabled = true;
    }
}
```

`GetYourExistingSqlServerConnectionString()` is a placeholder for the actual connection-string property or method in your existing SQL Server class.

## 8. Required project references

For a .NET Framework Windows Forms project, install or reference:

| Library                   | Purpose                               |
| ------------------------- | ------------------------------------- |
| `System.Data.SQLite.Core` | Read SQLite `.db` files               |
| `System.Data`             | DataTable and database infrastructure |
| `System.Data.SqlClient`   | SQL Server connection and bulk insert |
| `System.Xml.Linq`         | Read App.config.xml                   |
| `System.Windows.Forms`    | Desktop interface                     |

The configuration file should be copied to the application output directory.

For example:

```
bin/Debug/App.config.xml
```

Load it with:

```
TransferConfig config =
    ConfigLoader.Load(
        Path.Combine(
            Application.StartupPath,
            "App.config.xml"));
```

Important: I am treating `App.config.xml` as a standalone XML file loaded through `XDocument`. If you rename it to the standard .NET `App.config`, the custom XML elements must be declared as configuration sections first. The implementation above intentionally avoids that requirement.

## 9. Important things to consider before production

There are four points I want to highlight.

1\. One-to-many joins can multiply records.

For example, if a student has three competition results and two detail records, joining both child tables can produce six rows. This may be correct for your report, but we need to verify that this is what you intend.

2\. Destination column names must be unique.

Suppose both Student and StudentDetails contain a column called `StudentID`. If both are transferred to the same destination, use explicit destination mappings to avoid duplicate columns.

For example:

```
<add key="StudentDetails"
     root="Student"
     alias="sd"
     joinType="LEFT"
     joinCondition="s.StudentID=sd.StudentID"
     value="StudentID,Email,Phone"
     destinationColumns="DetailsStudentID,Email,Phone" />
```

3\. TestRun date and line columns are currently metadata.

The implementation loads `TestRunPropertyTestDateColumnName` and `TestRunPropertyTestLineColumnName`, but does not use them to filter records. We should add filtering only after establishing exactly how those fields determine which records should be transferred.

4\. SQL Server destination tables must already exist.

The current implementation expects the destination tables and their mapped columns to exist. It does not create tables or update existing records. It performs inserts. If a transfer fails, the SQL Server transaction is rolled back.

## 10. My recommendation before integrating this with your existing database classes

I would like to see the actual method signatures of these two existing classes:

- `SQLiteDatabase`
- `SQLServerDatabase`

Then I can refactor `DataTransferEngine` to call your existing methods instead of creating new database connections.

Also, there is one important behavior to confirm: Should every record in each configured TestRun table be transferred, or should the application transfer only records belonging to a particular TestRun date and TestLine?

That will determine how we use the two date and line column settings already present in your configuration.
