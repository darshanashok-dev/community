"""Local entry point for running the Cybersecurity Awareness Platform."""

from app import create_app

app = create_app()


if __name__ == "__main__":
    host = app.config["HOST"]
    port = app.config["PORT"]
    print(f"CyberShield Awareness running at http://{host}:{port} (Press CTRL+C to quit)", flush=True)
    app.run(
        host=host,
        port=port,
        debug=app.config["DEBUG"],
    )
