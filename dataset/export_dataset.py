"""Export synthetic SQLite database tables into clean CSV files for the dataset tech stack."""
from __future__ import annotations

import csv
import sqlite3
from pathlib import Path

DATASET_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = DATASET_DIR.parent
DB_PATH = PROJECT_ROOT / "data" / "agent_shield.db"


def export_tables() -> None:
    DATASET_DIR.mkdir(parents=True, exist_ok=True)
    if not DB_PATH.exists():
        print(f"Database not found at {DB_PATH}")
        return

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    tables = [
        "customers",
        "loans",
        "payments",
        "employees",
        "payroll",
        "agents",
        "permissions",
        "behaviour_baselines",
    ]

    for tbl in tables:
        rows = conn.execute(f"SELECT * FROM {tbl}").fetchall()
        if rows:
            keys = rows[0].keys()
            csv_path = DATASET_DIR / f"{tbl}.csv"
            with open(csv_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(keys)
                for r in rows:
                    writer.writerow([r[k] for k in keys])
            print(f"Exported {len(rows):>4} records -> dataset/{tbl}.csv")

    schema_path = DATASET_DIR / "schema.sql"
    with open(schema_path, "w", encoding="utf-8") as f:
        for row in conn.execute("SELECT sql FROM sqlite_master WHERE type IN ('table', 'index') AND sql IS NOT NULL"):
            f.write(row[0] + ";\n\n")
    print(f"Exported database DDL -> dataset/schema.sql")

    conn.close()


if __name__ == "__main__":
    export_tables()
