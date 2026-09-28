from flask import Flask, request
import sqlite3

app = Flask(__name__)

DATABASE = "lab.db"


def init_db():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY,
            name TEXT,
            price REAL
        )
    """)

    cursor.execute("DELETE FROM products")

    cursor.executemany(
        "INSERT INTO products (id, name, price) VALUES (?, ?, ?)",
        [
            (1, "Laptop", 999.99),
            (2, "Keyboard", 49.99),
            (3, "Mouse", 29.99),
            (4, "Monitor", 249.99),
        ]
    )

    conn.commit()
    conn.close()


@app.route("/")
def home():
    return """
    <h1>SQL Injection Lab</h1>

    <p>This is a local intentionally vulnerable application.</p>

    <p>Try:</p>

    <ul>
        <li><a href="/item?id=1">Item 1</a></li>
        <li><a href="/item?id=2">Item 2</a></li>
        <li><a href="/item?id=3">Item 3</a></li>
    </ul>
    """


@app.route("/item")
def item():
    item_id = request.args.get("id", "1")

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    # INTENTIONALLY VULNERABLE:
    # User input is inserted directly into the SQL query.
    query = f"SELECT id, name, price FROM products WHERE id = {item_id}"

    try:
        cursor.execute(query)
        results = cursor.fetchall()

        if results:
            output = "<h1>Product Results</h1>"

            for product in results:
                output += f"""
                <p>
                    ID: {product[0]}<br>
                    Name: {product[1]}<br>
                    Price: ${product[2]}
                </p>
                """

            return output

        return "<h1>No products found.</h1>"

    except sqlite3.Error as error:
        return f"""
        <h1>Database Error</h1>
        <p>{error}</p>
        """

    finally:
        conn.close()


if __name__ == "__main__":
    init_db()

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )
