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



---

# Full doc

DATA AGGREGATOR | TECHNICAL DESIGN 

# **DATA AGGREGATOR REFACTORING** 

Configuration-Driven Table Definitions, Relationships, and SQL Server Schema Management 

_Technical Design Document | 13 November 2026_ 

## **Document purpose** 

This document describes a proposed refactoring of the Data Aggregator based on the supplied app.config XML. It defines how table metadata, parent-child relationships, key constraints, SQL Server table creation, and data aggregation should be organized. The design deliberately reuses the existing SQLite reader and SQLServer.cs implementation rather than replacing them. 

This is a design proposal. Existing class names, constructors, and method signatures must be checked against the actual codebase before implementation. 

## **1. Objectives** 

- Move table-specific metadata and relationships out of hardcoded C# logic and into app.config. 

- Support Property, Root, and Child table classifications. 

- Represent logical parent relationships even though the source SQLite database does not declare foreign keys. 

- Support composite parent-child relationships through multiple configured column pairs. 

- Centralize SQL Server schema creation and constraint management in SQLServer.cs. 

- Process tables in dependency order so parent destination tables exist before dependent child tables. 

- Reuse existing SQLite DataTable retrieval and SQL Server insert/update functionality. 

- Provide a foundation for safely reprocessing historical source databases without duplicate destination records. 

## **2. Scope and non-goals** 

### **In scope** 

- Parsing and validating the supplied table configuration. 

- Resolving logical parent references and computing parent-before-child order. 

- Creating destination columns, primary keys, unique constraints, and optional foreign-key constraints in SQL Server. 

- Passing each source DataTable and its table metadata to the existing SQL Server data persistence logic. 

- Testing configuration validity, schema creation, relationship constraints, and repeat processing. 

### **Out of scope for this refactoring unless separately approved** 

- Replacing the existing SQLite reader or SQL Server data access layer. 

- Joining or filtering source SQLite DataTables using JoinConditions. 

- Automatically inferring business relationships that are not explicitly configured. 

- Changing the source SQLite schema or adding foreign keys to source databases. 

- Implementing unrelated SUT serial number, CSC, or HIC enhancements; those may be separate follow-up stories. 

Proposed design — validate implementation details against existing SQLite and SQLServer.cs APIs 

DATA AGGREGATOR | TECHNICAL DESIGN 

## **3. Supplied configuration and table model** 

The supplied XML defines four logical tables and three parent-child relationships: 

TestRunProperty (Property) └── MOSS (Root) └── MOSS_Child (Child) └── MOSS_Child_2 (Child) 

|**Logical name**|**Type**|**SQLite source**|**SQL Server destination**|**Parent**|
|---|---|---|---|---|
|TestRunProperty|Property|TestRunProperty|SDA_TestRunProperty|—|
|MOSS|Root|MOSS_table|SDA_MOSS|TestRunProperty|
|MOSS_Child|Child|MOSS_Child_table|SDA_MOSS_Child|MOSS|
|MOSS_Child_2|Child|MOSS_Child_table_2|SDA_MOSS_Child_2|MOSS_Child|



The table type and parent are separate concepts. A Root table can have a Property parent, and a Child table can itself be the parent of another Child table. The parent attribute identifies the logical parent definition by its name attribute. 

### **3.1 Attribute definitions** 

|**Attribute / element**|**Meaning**<br>i    i|
|---|---|
|name|Unique logical identifier used by the configuration and parent<br>references.<br>i|
|type|Classification: Property,Root,or Child.|
|sourceTable|Table name in the source SQLite database.|
|destinationTable|Table name to create/use in SQL Server.|
|parent|Logicalparent table name;absent for a top-level table.|
|primaryKey|Comma-separated destination column list for theprimarykey.|
|uniqueKey|Comma-separated destination column list for a unique<br>constraint.|
|JoinConditions|Ordered parentColumn/childColumn pairs defining the<br>relationship.|
|Columns/Column|Source-to-destination column mapping. If destination is omitted,<br>use source name.|



## **4. Relationship and join-condition semantics** 

The source SQLite database has no declared foreign-key constraints. Therefore, the relationships in this configuration are application-supplied metadata. JoinConditions describe corresponding columns between a destination parent table and a destination child table. 

<JoinConditions operator="AND"> <Condition parentColumn="MOSS_ID" childColumn="MOSS_ID" /> <Condition parentColumn="TestRunID" childColumn="TestRunID" /> </JoinConditions> 

For a physical SQL Server composite foreign key, the column pairs are treated together as one composite relationship. SQL Server foreign keys do not support an OR relationship across column pairs. The operator should therefore be AND for any relationship that is emitted as a foreign-key constraint. If OR is ever needed for application-level matching, it must be modeled separately and must not be translated into a SQL Server foreign key. 

JoinConditions are not instructions to join, filter, or merge source SQLite DataTables. The aggregator reads each configured source table independently. It passes relationship metadata to SQLServer.cs for destination schema creation and validation. 

### **4.1 Relationship definitions in the supplied XML** 

**<mark>Child destination</mark>** 

**<mark>Child columns</mark>** 

**<mark>Parent destination</mark>** 

**<mark>Parent columns</mark>** 

Proposed design — validate implementation details against existing SQLite and SQLServer.cs APIs 

DATA AGGREGATOR | TECHNICAL DESIGN 

|SDA_MOSS|SDA_TestRunProperty|PropertyID,TestRunID|PropertyID,TestRunID|
|---|---|---|---|
|SDA_MOSS_Child|SDA_MOSS|MOSS_ID,TestRunID|MOSS_ID,TestRunID|
|SDA_MOSS_Child_2|SDA_MOSS_Child|Child_ID,TestRunID|Child_ID,TestRunID|



## **5. Primary keys, unique constraints, and foreign keys** 

### **5.1 Primary keys** 

The primaryKey attribute identifies the primary-key columns for the destination table. SQLServer.cs is responsible for generating and executing the corresponding PRIMARY KEY constraint. 

### **5.2 Unique constraints** 

The uniqueKey attribute identifies a candidate key that SQL Server must enforce. It may also be needed as the referenced key for a composite foreign key. The unique-key definition must not be removed merely because one of its columns is already a primary key if a child foreign key references the exact composite column list. 

For example, MOSS_Child has PRIMARY KEY (Child_ID), but MOSS_Child_2 references (Child_ID, TestRunID). SQL Server requires a unique key/index on the referenced parent column set, so UNIQUE (Child_ID, TestRunID) is needed for that configured composite reference. The same reasoning applies to MOSS and its child relationship. If the business relationship can instead reference only the single primary-key column, the XML and FK can be simplified together. 

### **5.3 Foreign keys** 

A foreign key is created by SQLServer.cs only when the configuration requests/permits it and the parent table has already been created. The referenced parent columns must be backed by a primary key or a matching unique constraint/index, in the same order. Parent and child column data types must be compatible. Existing source data must satisfy the relationship before the constraint can be enabled. 

### **5.4 Existing-table and rerun behavior** 

CREATE TABLE fails if the destination table already exists. The implementation must decide whether schema creation is create-if-missing, schema reconciliation, or a controlled migration. Historical reprocessing should not blindly drop and recreate destination tables. Constraint creation must also be idempotent and should detect whether the expected constraint already exists. 

## **6. Important configuration gap: destination column data types** 

The supplied XML lists source and destination column names but does not specify SQL Server data types or nullability. SQL Server cannot create a typed destination table from column names alone. Before implementation, select one of these approaches: 

1. Preferred if supported by the existing code: obtain source SQLite schema metadata through the existing SQLite component and map SQLite types to approved SQL Server types, with explicit overrides where needed. 

2. Add type and nullable attributes to each Column element in app.config, for example: <Column source="Child_ID" type="INT" nullable="false" />. 

3. Use a centralized mapping table in configuration/code that maps known source column types to SQL Server types. 

The chosen approach must define how SQLite's flexible/dynamic typing, NULL values, text lengths, numeric precision, and unmapped types are handled. Do not concatenate arbitrary unvalidated type strings into SQL. 

Proposed design — validate implementation details against existing SQLite and SQLServer.cs APIs 

DATA AGGREGATOR | TECHNICAL DESIGN 

## **7. Proposed component responsibilities** 

|**Component**|**Responsibilities**|**Must not do**|
|---|---|---|
|app.config|Declare table metadata, keys, column<br>mappings, parent references, and<br>relationshipcolumnpairs.<br>i|Contain executable SQL or data-<br>processing logic.|
|AggregatorConfig|Parse XML, validate definitions, resolve<br>parents,calculate dependencyorder.|Read or write database records.|
|DataAggregator|Coordinate reading, destination schema<br>preparation, and persistence in<br>dependencyorder.|Implement SQL DDL/DML or source-table<br>joins.|
|Existing SQLite reader|Read each source table into a DataTable;<br>optionally expose source schema<br>metadata if needed.|Create SQL Server constraints.|
|SQLServer.cs|Create/validate destination schema and<br>constraints; insert/update destination<br>data.|Determine configuration dependency<br>order.|



## **8. Proposed C# model** 

public enum TableType { Property, Root, Child } public class TableDefinition { public string Name { get; set; } public TableType Type { get; set; } public string SourceTable { get; set; } public string DestinationTable { get; set; } public string Parent { get; set; } public string PrimaryKey { get; set; } public string UniqueKey { get; set; } public string JoinOperator { get; set; } public List<JoinCondition> JoinConditions { get; set; } = new List<JoinCondition>(); public List<ColumnMapping> Columns { get; set; } = new List<ColumnMapping>(); } public class JoinCondition { public string ParentColumn { get; set; } public string ChildColumn { get; set; } } public class ColumnMapping { public string Source { get; set; } public string Destination { get; set; } // Add DataType and Nullable if types are explicitly configured. } 

Proposed design — validate implementation details against existing SQLite and SQLServer.cs APIs 

DATA AGGREGATOR | TECHNICAL DESIGN 

The parser should default Destination to Source when the destination attribute is omitted. The current supplied XML uses this convention for most columns. 

## **9. Configuration loading and validation** 

The custom aggregator section is declared using System.Configuration.IgnoreSection so that the application configuration remains valid to the .NET configuration system while the application reads the XML section directly with XDocument. The parser should load the executable's actual .config file (typically application.exe.config), not assume that a source app.config file is deployed under its original name. 

- Require a unique, non-empty logical name for every Table. 

- Require sourceTable and destinationTable for every Table. 

- Accept only Property, Root, and Child as table types. 

- Require a parent for Child tables; permit a parent for Root and Property tables. 

- Verify every parent reference resolves to exactly one configured table. 

- Reject circular parent dependencies. 

- Validate that JoinConditions have non-empty parentColumn and childColumn values. 

- Validate that each join column exists in the relevant destination column definitions or can be resolved from the source schema. 

- Validate primary-key and unique-key column lists against destination columns. 

- Validate SQL Server type definitions and nullability using an approved mapping/allowlist. 

- Validate that foreign-key parent columns are backed by an exact matching candidate key and that child/parent data types are compatible. 

## **10. Aggregation workflow** 

4. Load the aggregator configuration. 

5. Parse all table definitions and column mappings. 

6. Validate table names, types, keys, join columns, parent references, and cycles. 

7. Calculate a parent-before-child processing order. 

8. For each table in that order, read the source SQLite table into a DataTable using the existing SQLite reader. 

9. Ensure the destination table and its configured constraints exist using SQLServer.cs. The parent destination must be available before a child foreign key is created. 

10. Pass the table definition and DataTable to the existing SQL Server insert/update operation. 

11. Log the table name, source row count, destination action, and any errors. 

12. Report overall success/failure and retain enough diagnostic information to retry safely. 

The aggregator does not perform joins between source DataTables. JoinConditions are passed as schema metadata only. 

## **11. SQL Server DDL example** 

For SDA_MOSS_Child, the intended schema may resemble the following. The actual data types must be confirmed from source schema or explicit type configuration. 

CREATE TABLE [SDA_MOSS_Child] ( 

[Child_ID] INT NOT NULL, 

[MOSS_ID] INT NOT NULL, 

- [TestRunID] INT NOT NULL, 

- [Child_Name] NVARCHAR(255) NULL, 

Proposed design — validate implementation details against existing SQLite and SQLServer.cs APIs 

DATA AGGREGATOR | TECHNICAL DESIGN 

CONSTRAINT [PK_SDA_MOSS_Child] PRIMARY KEY ([Child_ID]), 

CONSTRAINT [UQ_SDA_MOSS_Child] UNIQUE ([Child_ID], [TestRunID]), 

CONSTRAINT [FK_SDA_MOSS_Child_SDA_MOSS] FOREIGN KEY ([MOSS_ID], [TestRunID]) REFERENCES [SDA_MOSS] ([MOSS_ID], [TestRunID]) ); 

The unique constraint shown is needed if a downstream table references the exact (Child_ID, TestRunID) pair, even though Child_ID alone is the primary key. If no downstream composite FK uses that pair, it may be unnecessary. 

## **12. Insert/update behavior and historical reprocessing** 

SQLServer.cs (or the existing persistence method it exposes) is responsible for inserting new rows and updating existing rows. It should use a configured, stable matching key to determine whether a destination record already exists. This behavior is distinct from creating primary-key, unique, and foreign-key constraints. 

- New source records are inserted. 

- Existing destination records with the same configured matching key are updated when source values differ. 

- Repeated processing of the same source database does not create duplicate records. 

- Newly configured tables can be added for historical runs without duplicating the existing test run. 

- Schema changes are handled through controlled, idempotent schema evolution rather than destructive table recreation. 

The current XML's primaryKey and uniqueKey attributes describe SQL Server constraints. The team must explicitly decide which key is used by the insert/update matching logic; do not assume the two concepts are interchangeable. The source run identity and TestRunID mapping must also be confirmed. 

## **13. Error handling, logging, and transaction considerations** 

- Fail configuration validation before starting database writes when a required definition is invalid. 

- Use parameterized SQL for data values. SQL identifiers cannot be parameterized, so validate and safely quote all table/column/constraint identifiers. 

- Restrict SQL type declarations to approved types or derive them from trusted schema metadata. 

- Log table-level start/end, row counts, schema actions, and exceptions without logging sensitive data unnecessarily. 

- Define transaction boundaries. At minimum, schema creation for one table and its constraints should be consistent; data insertion transaction scope should align with existing SQLServer.cs behavior. 

- On a foreign-key violation, report the child table, parent table, and configured column pairs. 

- Do not silently disable constraints or discard orphan records; define an explicit remediation policy. 

## **14. Testing strategy** 

|**Test area**|**Test case / expected result**|
|---|---|
|Configuration parsing|All four supplied table definitions load with correct attributes and<br>column mappings.|
|Default mapping|Column with no destination attribute maps destination to source<br>name.|
|Dependency ordering|Order is TestRunProperty, MOSS, MOSS_Child, MOSS_Child_2<br>even if XML definitions are rearranged.|
|Parent validation|Unknownparent is rejected before aggregation.|



Proposed design — validate implementation details against existing SQLite and SQLServer.cs APIs 

DATA AGGREGATOR | TECHNICAL DESIGN 

|Cycle detection|Circularparent references are rejected.|
|---|---|
|Composite relationship|Two join-condition pairs generate one composite FK with<br>matchingorder.|
|Primary/unique constraints|Configured constraints are created and verified in SQL Server.|
|Candidate key validation|FK creation fails validation if parent does not have matching<br>PK/unique key.|
|Type compatibility|Incompatible parent/child column types are detected before FK<br>creation.|
|Existing destination|Rerunning schema setup does not fail merely because the<br>table/constraint alreadyexists.|
|Data persistence|New rows insert and existing matching rows update according to<br>the agreed matchingkey.|
|Historical rerun|Reprocessing the same source does not duplicate test runs or<br>detail records.|
|Orphan data|Invalid child references are reported and handled according to<br>an agreedpolicy.|



## **15. Decisions required before implementation** 

13. Column data-type strategy: infer from SQLite schema, add type/nullability to XML, or use a centralized mapping. 

14. Whether all configured JoinConditions should create physical SQL Server foreign keys, or whether FK creation needs a separate explicit flag (recommended for control over legacy/orphan data). 

15. Whether the insert/update matching key is always uniqueKey, primaryKey, or a separate configurable aggregationKey. 

16. How destination schema changes are applied when a new column is added to a table that already exists. 

17. Whether a table's schema and data operations run in one transaction or separate controlled transactions. 

18. How source TestRun identity maps to the destination TestRunID during historical reprocessing. 

## **16. Acceptance criteria** 

- The application loads and validates the supplied configuration. 

- Property, Root, and Child definitions are supported. 

- A Root may have a parent, and a Child may parent another Child. 

- Parent references are resolved by logical table name. 

- Tables are processed in parent-before-child order. 

- Each configured SQLite source table is read independently into a DataTable by the existing reader. 

- JoinConditions are not used to join or filter source SQLite data. 

- SQLServer.cs creates destination columns and configured PK/unique constraints. 

- SQLServer.cs creates physical FKs only when enabled and valid, including candidate-key and type checks. 

- Schema setup is safe to rerun and does not destructively recreate existing destination tables. 

- Existing insert/update functionality is reused or extended to support deterministic, duplicate-safe reprocessing. 

- Invalid configuration, dependency cycles, incompatible keys/types, and FK violations produce actionable errors. 

- Automated tests cover configuration, ordering, schema generation, and historical reprocessing. 

## **17. Implementation task breakdown** 

|**Subtask**|**Description**|
|---|---|
|1. Configuration schema|Finalize XML contract and document attributes, defaults, and<br>optional elements.|
|2. Configurationparser|Implement table,column,key,and JoinConditionsparsing.|
|3. Configuration validation|Validate names, types, parents, cycles, keys, join columns, and<br>SQL type metadata.|
|4. Dependency ordering|Implement parent-before-child ordering independent of XML<br>order.|
|5. SQL Server schemageneration|Extend SQLServer.cs to create columns, primarykeys,unique|



Proposed design — validate implementation details against existing SQLite and SQLServer.cs APIs 

DATA AGGREGATOR | TECHNICAL DESIGN 

||constraints,and optional foreign keys.|
|---|---|
|6. Schema idempotency/evolution|Handle existing tables and constraints safely; define additive<br>schema changes.|
|7. Data persistence integration|Connect DataTables to existing insert/update logic using the<br>agreed matchingkey.|
|8. Historical reprocessing|Verify repeat processing updates existing records and does not<br>duplicate runs/details.|
|9. Automated tests|Add unit and integration tests for all acceptance criteria.|
|10. Operational documentation|Document how to add a table, define a parent, configure keys,<br>and troubleshoot failures.|



## **Appendix A. Supplied configuration** 

<?xml version="1.0" encoding="utf-8"?> <configuration> <configSections> <section name="aggregator" type="System.Configuration.IgnoreSection, System.Configuration" allowLocation="true" allowDefinition="Everywhere" /> </configSections> <aggregator> <Tables> <Table name="TestRunProperty" type="Property" sourceTable="TestRunProperty" destinationTable="SDA_TestRunProperty" primaryKey="PropertyID" uniqueKey="PropertyID,TestRunID"> <Columns> <Column source="PropertyID" /> <Column source="TestRunID" /> <Column source="PropertyName" /> <Column source="PropertyValue" /> </Columns> </Table> <Table name="MOSS" type="Root" sourceTable="MOSS_table" destinationTable="SDA_MOSS" parent="TestRunProperty" primaryKey="MOSS_ID" uniqueKey="MOSS_ID,TestRunID"> <JoinConditions operator="AND"> <Condition parentColumn="PropertyID" childColumn="PropertyID" /> <Condition parentColumn="TestRunID" childColumn="TestRunID" /> </JoinConditions> <Columns> <Column source="MOSS_ID" /> <Column source="PropertyID" /> <Column source="TestRunID" /> <Column source="MOSS_Name" destination="MOSS_Name" /> </Columns> </Table> <Table name="MOSS_Child" type="Child" sourceTable="MOSS_Child_table" destinationTable="SDA_MOSS_Child" parent="MOSS" primaryKey="Child_ID" uniqueKey="Child_ID,TestRunID"> <JoinConditions operator="AND"> 

Proposed design — validate implementation details against existing SQLite and SQLServer.cs APIs 

DATA AGGREGATOR | TECHNICAL DESIGN 

<Condition parentColumn="MOSS_ID" childColumn="MOSS_ID" /> <Condition parentColumn="TestRunID" childColumn="TestRunID" /> </JoinConditions> <Columns> <Column source="Child_ID" /> <Column source="MOSS_ID" /> <Column source="TestRunID" /> <Column source="Child_Name" /> </Columns> </Table> <Table name="MOSS_Child_2" type="Child" sourceTable="MOSS_Child_table_2" destinationTable="SDA_MOSS_Child_2" parent="MOSS_Child" primaryKey="Child2_ID" uniqueKey="Child2_ID,TestRunID"> <JoinConditions operator="AND"> <Condition parentColumn="Child_ID" childColumn="Child_ID" /> <Condition parentColumn="TestRunID" childColumn="TestRunID" /> </JoinConditions> <Columns> <Column source="Child2_ID" /> <Column source="Child_ID" /> <Column source="TestRunID" /> <Column source="Description" /> </Columns> </Table> </Tables> </aggregator> </configuration> 

## **Appendix B. JIRA-ready story text** 

Use the following condensed content in the JIRA issue description. Attach this document as the detailed technical design. 

### **Story title** 

Refactor Data Aggregator to Use Configuration-Driven Table Definitions and SQL Server Relationships 

### **Description** 

Refactor the existing Data Aggregator to define source/destination tables, table types, column mappings, keys, and parent-child relationships in app.config. The source SQLite databases do not declare foreign keys, so logical relationships must be configured explicitly. The aggregator will validate configuration and process tables in parent-before-child order. The existing SQLite reader will continue returning DataTables. SQLServer.cs will own destination schema creation, primary-key/unique constraints, optional foreign-key constraints, and data insert/update operations. JoinConditions are destination schema metadata only and must not be used to join or filter SQLite source data. 

### **Business / technical value** 

- Reduce hardcoded table-specific logic and make new tables configurable. 

- Support Property, Root, and Child table types, including Root tables with parents and nested Child relationships. 

- Support composite parent-child relationships. 

- Reuse existing database access components and improve maintainability. 

- Enable safe historical reprocessing without duplicate records. 

Proposed design — validate implementation details against existing SQLite and SQLServer.cs APIs 

DATA AGGREGATOR | TECHNICAL DESIGN 

### **Acceptance criteria** 

- Configuration loads and validates all table definitions. 

- Parent references and cycles are validated; tables are processed parent first. 

- Column mappings support destination-name defaulting to source name. 

- Configured primary and unique constraints are created by SQLServer.cs. 

- Configured foreign keys are created only when parent candidate keys, column order, and data types are valid. 

- JoinConditions are not executed as source SQLite joins or filters. 

- Schema creation is idempotent and does not drop/recreate existing tables during routine reprocessing. 

- Existing insert/update logic uses an agreed stable matching key and prevents duplicate records on reruns. 

- Unit and integration tests cover the supplied four-table hierarchy and failure cases. 

### **Implementation subtasks** 

- Finalize configuration contract and SQL type strategy. 

- Implement configuration parsing and validation. 

- Implement parent-before-child dependency ordering. 

- Extend SQLServer.cs for destination columns and constraints. 

- Integrate existing SQLite DataTable reader and SQL Server persistence methods. 

- Implement safe schema rerun/evolution behavior. 

- Test composite relationships, invalid references, and historical reprocessing. 

### **Dependencies / open decisions** 

- Confirm how SQL Server column types and nullability are obtained; the supplied XML currently omits them. 

- Confirm whether configured relationships always create physical foreign keys or require an explicit enable flag. 

- Confirm whether uniqueKey is also the data upsert matching key or whether a separate aggregation key is required. 

- Confirm how existing destination tables are altered when new columns are introduced. 

- Confirm the source-to-destination TestRunID identity mapping for historical processing. 

Proposed design — validate implementation details against existing SQLite and SQLServer.cs APIs 


