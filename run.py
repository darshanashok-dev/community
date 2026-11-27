"""Local entry point for running the Cybersecurity Awareness Platform."""

from app import create_app

app = create_app()


if __name__ == "__main__":
    app.run(
        host=app.config["HOST"],
        port=app.config["PORT"],
        debug=app.config["DEBUG"],
    )
