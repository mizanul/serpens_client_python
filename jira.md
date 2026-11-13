# JIRA Story: Refactor Data Aggregator to Support Configuration-Driven Table Relationships and SQL Server Schema Creation



Proposed implementation

Technical design



## 1. Summary

Refactor the existing Data Aggregator to support a flexible, configuration-driven approach for defining SQLite source tables, SQL Server destination tables, table relationships, primary keys, unique constraints, and foreign-key constraints.

The objective is to reduce hardcoded table-specific logic and make it easier to add new tables and relationships without modifying the aggregator's core implementation.

The solution will use `app.config` to define table metadata and relationships. The existing SQLite reader and `SQLServer.cs` implementations will be reused and extended where necessary.

## 2. Background / Problem Statement

The current Data Aggregator needs a more maintainable and scalable approach to handling different table structures and relationships.

The source SQLite databases do not define foreign-key relationships. Therefore, the logical relationships between tables must be explicitly defined in the aggregator configuration.

The existing implementation should be refactored to:

- Reduce hardcoded table definitions and relationships.
- Support different table types, including Property, Root, and Child.
- Support multiple parent-child join conditions.
- Support primary-key and unique-key definitions.
- Generate SQL Server foreign-key constraints when appropriate.
- Allow new tables and relationships to be introduced through configuration.
- Support historical data reprocessing without creating duplicate records.
- Reuse existing SQLite data-reading and SQL Server data-writing functionality.

## 3. Proposed Architecture

The proposed architecture separates configuration, orchestration, SQLite data access, and SQL Server schema/data operations.

app.config

Table definitions, column mappings, keys and relationships

AggregatorConfig.cs

Load, parse and validate configuration

DataAggregator.cs

Determine dependency order and orchestrate aggregation

Existing SQLite Reader

Read source tables into DataTables

Existing SQLServer.cs

Create tables, keys, relationships and insert/update data

### Component responsibilities

| Component               | Responsibility                                                            |
| ----------------------- | ------------------------------------------------------------------------- |
| `app.config`            | Define table metadata, column mappings, keys, and relationships           |
| `AggregatorConfig.cs`   | Parse and validate configuration                                          |
| `DataAggregator.cs`     | Process tables in parent-before-child dependency order                    |
| Existing SQLite class   | Read SQLite source tables into `DataTable` objects                        |
| Existing `SQLServer.cs` | Create destination tables, keys, relationships, and insert/update records |

The aggregator will not implement its own SQLite reader or SQL Server writer.

## 4. Table Classification and Relationship Model

Introduce three table types:

| Table type | Description                                                                               |
| ---------- | ----------------------------------------------------------------------------------------- |
| `Property` | Stores properties associated with a test run or another logical entity                    |
| `Root`     | Represents a root-level data table; it may have a Property or another table as its parent |
| `Child`    | Represents a child table associated with another table                                    |

Important: Table type and parent relationship are independent concepts. A Root table does not necessarily have to be parentless. A Property table can also be a parent of another table.

### Example hierarchy

```
TestRunProperty (Property)
        |
        v
MOSS (Root)
        |
        v
MOSS_Child (Child)
        |
        v
MOSS_Child_2 (Child)
```

The relationship is defined by the `parent` attribute in the child table's configuration.

## 5. Configuration Design

Use `app.config` to define the source and destination table information.

Each table definition should support:

| Attribute          | Description                                                                   |
| ------------------ | ----------------------------------------------------------------------------- |
| `name`             | Logical table name used by the aggregator                                     |
| `type`             | Property, Root, or Child                                                      |
| `sourceTable`      | Source SQLite table name                                                      |
| `destinationTable` | Destination SQL Server table name                                             |
| `parent`           | Logical parent table name; optional for Property and Root, required for Child |
| `primaryKey`       | Destination primary-key columns                                               |
| `uniqueKey`        | Destination unique-key columns                                                |

Each table can also define:

- Column mappings.
- SQL Server data types.
- Nullability.
- Multiple parent-child join conditions.
- Join condition operator (`AND` or `OR`).

### Example configuration

```
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
        <Column source="Child_ID" type="INT" nullable="false" />
        <Column source="MOSS_ID" type="INT" nullable="false" />
        <Column source="TestRunID" type="INT" nullable="false" />
        <Column source="Child_Name"
                type="NVARCHAR(255)"
                nullable="true" />
    </Columns>

</Table>
```

The `JoinConditions` element describes the relationship between the parent and child destination tables. It is not used to join or filter SQLite source data.

## 6. Multiple Join Conditions

The configuration must support multiple join conditions for a relationship.

Example:

```
<JoinConditions operator="AND">
    <Condition parentColumn="MOSS_ID" childColumn="MOSS_ID" />
    <Condition parentColumn="TestRunID" childColumn="TestRunID" />
</JoinConditions>
```

This should generate the following SQL Server relationship:

```
FOREIGN KEY (MOSS_ID, TestRunID)
REFERENCES SDA_MOSS (MOSS_ID, TestRunID)
```

The initial implementation will support a single logical operator (`AND` or `OR`) for all conditions in a relationship. Physical composite foreign-key constraints require all participating column pairs; they cannot use `OR`. Therefore, `OR` may be supported for logical matching metadata only, not for generating a SQL Server foreign key. The implementation should reject `OR` when a physical foreign-key constraint is requested.

## 7. SQL Server Table Creation and Constraints

Extend the existing `SQLServer.cs` implementation to create destination tables dynamically using the table definitions supplied by the aggregator.

The table creation process should:

1. Create destination columns with configured SQL Server data types.
2. Apply column nullability.
3. Create primary-key constraints.
4. Create unique constraints.
5. Create foreign-key constraints when configured and valid.
6. Execute the generated SQL statement.

### Example generated SQL

```
CREATE TABLE SDA_MOSS_Child
(
    Child_ID INT NOT NULL,
    MOSS_ID INT NOT NULL,
    TestRunID INT NOT NULL,
    Child_Name NVARCHAR(255) NULL,

    CONSTRAINT PK_SDA_MOSS_Child
        PRIMARY KEY (Child_ID),

    CONSTRAINT FK_SDA_MOSS_Child_MOSS
        FOREIGN KEY (MOSS_ID, TestRunID)
        REFERENCES SDA_MOSS (MOSS_ID, TestRunID)
);
```

Note: If `Child_ID` is already the primary key, a unique constraint on `(Child_ID, TestRunID)` is redundant. The configuration should avoid creating unnecessary constraints.

SQL Server requires the referenced parent columns to have a matching primary-key or unique constraint. The child and parent columns must also have compatible data types and matching column order.

The implementation should validate these requirements before creating foreign keys.

## 8. Primary Key and Unique Key Handling

Primary-key and unique-key definitions should be configuration-driven.

Example:

```
primaryKey="Child_ID"
uniqueKey="Child_ID,TestRunID"
```

The SQL Server implementation will use these definitions when creating the destination table.

For historical aggregation and duplicate prevention, the configured unique key should also be used by the existing insert/update mechanism to identify records.

The design should distinguish between:

- Primary key: Identifies a row uniquely in the destination table.
- Unique key: Defines the business or aggregation key used to identify an existing record during reprocessing.

These keys may be the same or different, depending on the source data model.

## 9. Aggregation Processing Flow

The aggregator will process tables in dependency order.

For example:

```
1. Load app.config
2. Parse table definitions
3. Validate table definitions and relationships
4. Determine parent-before-child processing order
5. Read source SQLite table into DataTable
6. Create destination SQL Server table if necessary
7. Insert or update destination records
8. Continue with the next table
```

Example orchestration:

```
foreach (var table in config.GetTablesInDependencyOrder())
{
    DataTable data =
        sqliteReader.GetTableData(table.SourceTable);

    TableDefinition parentTable = null;

    if (!string.IsNullOrWhiteSpace(table.Parent))
    {
        parentTable = config.Tables.First(
            x => x.Name.Equals(
                table.Parent,
                StringComparison.OrdinalIgnoreCase));
    }

    sqlServer.CreateTable(table, parentTable);

    sqlServer.InsertOrUpdateData(table, data);
}
```

The method names above represent the intended integration points. Existing method signatures should be retained or adapted as appropriate.

### Important processing rule

The aggregator will not execute SQLite joins or filter child records using `JoinConditions`. It will read the configured source tables and pass their data to the existing SQL Server insertion/update mechanism.

## 10. Historical Data Reprocessing and Idempotency

The refactored aggregator should support reprocessing historical SQLite databases.

Requirements:

- Reprocessing the same source database must not create duplicate test runs.
- Existing destination records should be updated when source values change.
- Newly introduced tables should be created and populated for existing test runs.
- Newly introduced columns should be handled without duplicating existing records.
- The same aggregation engine should be reusable by future scripts or automated agents.

The configured keys and existing insert/update functionality should support this behavior.

A stable source database/test-run identity must be used to associate historical data with the correct destination test run. The exact identity mechanism should be confirmed against the existing implementation.

## 11. Configuration Validation

`AggregatorConfig.cs` should validate the configuration before aggregation begins.

Validation requirements:

- Every table must have a unique logical name.
- Every table must define a source and destination table.
- Table type must be valid (`Property`, `Root`, or `Child`).
- Every Child table must have a parent.
- Every configured parent must exist.
- Circular parent relationships must be rejected.
- Join conditions must reference valid parent and child columns.
- Primary-key and unique-key columns must exist in the destination definitions.
- SQL data types must be validated or restricted to an approved set.
- Foreign-key constraints must reference a valid parent key.
- Duplicate or conflicting constraint definitions must be rejected.

## 12. Additional Scope Considerations

The refactoring should also accommodate future aggregation requirements identified during the initial design discussion:

| Requirement                     | Proposed approach                                                                |
| ------------------------------- | -------------------------------------------------------------------------------- |
| SUT Serial Number aggregation   | Add configurable table and column mappings                                       |
| CSC model/version information   | Capture detailed CSC records in organized destination tables                     |
| HIC code representation         | Support a representative high-level HIC code where required                      |
| HIC code-to-description mapping | Store mappings per TestRun instead of relying on a manually maintained singleton |
| Historical data mining          | Reuse the same aggregation engine for existing SQLite databases                  |

These items may be implemented as separate tasks or follow-up stories depending on sprint scope.

## 13. Implementation Tasks

Suggested JIRA subtasks

- Task 1 – Refactor configuration structure: Define the `Property`, `Root`, and `Child` table types and table metadata in `app.config`.
- Task 2 – Implement configuration parser: Implement `AggregatorConfig.cs` to parse and validate table definitions, keys, column mappings, and relationships.
- Task 3 – Implement dependency ordering: Resolve parent-child dependencies and process tables in parent-before-child order.
- Task 4 – Extend SQL Server table creation: Update `SQLServer.cs` to dynamically create columns, primary keys, unique constraints, and configured foreign-key constraints.
- Task 5 – Integrate existing SQLite reader: Reuse existing SQLite methods to retrieve source tables as `DataTable` objects.
- Task 6 – Integrate existing insert/update logic: Reuse or extend existing SQL Server insertion/update methods to support configured keys and historical reprocessing.
- Task 7 – Implement configuration validation: Validate parent references, join columns, key definitions, data types, and circular dependencies.
- Task 8 – Historical reprocessing support: Verify idempotent processing of previously aggregated test runs.
- Task 9 – Unit and integration testing: Test Property, Root, Child, composite relationships, and historical reprocessing.
- Task 10 – Documentation: Document how to add new tables and define their relationships through configuration.

## 14. Acceptance Criteria

The work will be considered complete when:

1. The aggregator can load table definitions from `app.config`.
2. New tables can be added without modifying the aggregator's core orchestration code.
3. Property, Root, and Child table types are supported.
4. Root tables can have parents.
5. Child tables can be parents of other Child tables.
6. Multiple join-condition column pairs can be configured.
7. The aggregator processes tables in the correct dependency order.
8. SQL Server tables are created using configured column definitions.
9. Primary-key and unique constraints are created according to configuration.
10. Foreign-key constraints are created when configured and valid.
11. Existing SQLite and SQL Server functionality is reused rather than unnecessarily duplicated.
12. Existing records are updated rather than duplicated during historical reprocessing.
13. Invalid or circular table relationships are detected before aggregation.
14. The configuration and aggregation engine can accommodate future table additions.

## 15. Expected Benefits

- Reduced coupling between table definitions and application code.
- Easier maintenance and extension of the aggregation process.
- Consistent SQL Server schema generation.
- Explicit and manageable parent-child relationships.
- Support for composite relationships.
- Improved historical data reprocessing.
- Reusable aggregation logic for future automation and data-mining activities.

## Suggested JIRA technical discussion note

You can add this comment to the ticket to clarify the design decision:

> The proposed design keeps the aggregator responsible for configuration-driven orchestration and dependency ordering. SQLite data access remains in the existing SQLite implementation, while SQL Server schema creation, primary-key/unique-key/foreign-key creation, and insert/update operations remain in `SQLServer.cs`.
>
> Since the source SQLite databases do not define foreign-key constraints, logical relationships will be defined in `app.config`. The aggregator will pass this metadata to the SQL Server implementation. `JoinConditions` will be used for destination schema relationship creation, not for joining or filtering source SQLite records.
>
> This approach minimizes changes to existing database access components and provides a scalable way to add new tables and relationships through configuration.

My recommendation: Use this as the main JIRA story and split the implementation tasks into subtasks. Keep the SUT SN, CSC, and HIC mapping enhancements as separate stories if they are too large for the same sprint.
