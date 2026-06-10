"""
Launch the Sentinellama web GUI.

    python run_web.py

Then open http://127.0.0.1:8000 in your browser.

To control the live Security-log monitor from the dashboard, launch this from
an *elevated* (Administrator) terminal — reading the Windows Security log
requires admin rights. Manual analysis and knowledge-base search work without
elevation.
"""
import uvicorn

if __name__ == "__main__":
    uvicorn.run("app:app", host="127.0.0.1", port=8000, reload=False)
