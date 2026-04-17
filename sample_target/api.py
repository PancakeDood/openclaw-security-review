from fastapi import FastAPI

app = FastAPI()
debug = True
allow_anonymous = True

@app.post("/run")
def run_job():
    return {"status": "ok"}
