# JIRA Story: Refactor Data Aggregator to Use Configuration-Driven Table Definitions and SQL Server Relationships

## Description
Refactor the existing Data Aggregator to define source/destination tables, table types, column mappings, keys, and parent-child relationships in `app.config`. The source SQLite databases do not declare foreign keys, so logical relationships must be configured explicitly.

The aggregator will validate configuration and process tables in parent-before-child order. The existing SQLite reader will continue returning `DataTable` objects. `SQLServer.cs` will own destination schema creation, primary-key/unique constraints, optional foreign-key constraints, and data insert/update operations.

**Important:** `JoinConditions` describe destination parent/child relationship columns. They are not used to join or filter source SQLite data.

## Proposed table hierarchy
```text
TestRunProperty (Property)
  └── MOSS (Root)
        └── MOSS_Child (Child)
              └── MOSS_Child_2 (Child)
```

A Root may have a parent, and a Child may itself be the parent of another Child. Table type and parent relationship are independent.

## Component responsibilities
- `app.config`: table definitions, column mappings, keys, parent references, and join-condition column pairs.
- `AggregatorConfig`: parse and validate the configuration; resolve parent references; compute dependency order.
- `DataAggregator`: orchestrate processing in parent-before-child order.
- Existing SQLite reader: retrieve each source table as a `DataTable`.
- Existing `SQLServer.cs`: create destination columns and constraints; insert/update destination records.

## Key design details
1. `Property`, `Root`, and `Child` are the supported table types.
2. `sourceTable` identifies the SQLite table; `destinationTable` identifies the SQL Server table.
3. `parent` references another table's logical `name`.
4. `primaryKey` defines the destination primary-key columns.
5. `uniqueKey` defines a destination unique constraint/candidate key.
6. `JoinConditions` contains ordered parent/child column pairs for a composite relationship.
7. `Columns/Column` maps source columns to destination columns. If `destination` is omitted, default it to `source`.
8. A physical SQL Server foreign key can be created only when the parent columns have a matching primary key or unique constraint, the column order matches, and the parent/child data types are compatible. Foreign keys use AND semantics; OR cannot be represented by a SQL Server composite FK.
9. The supplied XML does not specify destination SQL data types or nullability. The implementation must either derive them from source schema metadata with controlled type mapping or add explicit `type` and `nullable` attributes.
10. Routine reprocessing must not drop/recreate existing destination tables. Schema creation/evolution and constraint creation must be idempotent.

## Acceptance criteria
- The configuration loads and validates all table definitions.
- Parent references and cycles are validated; tables are processed parent first.
- Property, Root, and Child types are supported, including Root-with-parent and nested Child relationships.
- Column mappings default destination name to source name when omitted.
- Configured primary and unique constraints are created by `SQLServer.cs`.
- Configured foreign keys are created only when parent candidate keys, column order, and data types are valid.
- `JoinConditions` are not executed as SQLite source joins or filters.
- Existing-table handling is safe and does not destructively recreate tables during routine reprocessing.
- Existing insert/update logic uses an agreed stable matching key and prevents duplicates on reruns.
- Unit/integration tests cover the supplied hierarchy, composite relationships, invalid parents, cycles, key validation, and historical reruns.

## Implementation subtasks
1. Finalize configuration contract and SQL type strategy.
2. Implement configuration parsing and validation.
3. Implement parent-before-child dependency ordering.
4. Extend `SQLServer.cs` for destination columns, primary keys, unique constraints, and optional foreign keys.
5. Integrate existing SQLite `DataTable` reader and SQL Server persistence methods.
6. Implement safe schema rerun/evolution behavior.
7. Test composite relationships, invalid references, and historical reprocessing.

## Open decisions / dependencies
- How are SQL Server column types and nullability obtained? They are not present in the supplied XML.
- Should configured relationships always create physical foreign keys, or should a separate `createForeignKey` flag control this?
- Is `uniqueKey` also the insert/update matching key, or is a separate `aggregationKey` required?
- How are existing destination tables altered when new columns are introduced?
- How is source TestRun identity mapped to destination `TestRunID` during historical reprocessing?

**Attachment:** `Data_Aggregator_Refactoring_Technical_Design.docx` contains the detailed design, example SQL, validation rules, testing strategy, implementation breakdown, and the supplied XML.
