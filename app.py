import os
import subprocess
import sys
import threading
import webbrowser
import pandas as pd
import numpy as np
from fastapi import FastAPI, UploadFile, File, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
from pydantic import BaseModel

app = FastAPI(title="Network Anomaly Detection API")

# Enable CORS for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Adjust in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DATASET_PATH = "data/full_dataset.csv"
GRAPH_IMG_PATH = "data/network_graph.png"
UPLOAD_PATH = "data/uploaded_dataset.csv"

# Optional: keep dataset in memory for fast pagination
dataset_df = None

def load_dataset():
    global dataset_df
    if os.path.exists(DATASET_PATH):
        try:
            # Only read some columns or limit rows if needed for speed, but 43MB is fine
            dataset_df = pd.read_csv(DATASET_PATH)
            dataset_df.replace([np.inf, -np.inf], np.nan, inplace=True)
            dataset_df.fillna("N/A", inplace=True)
        except Exception as e:
            print(f"Error loading dataset: {e}")

def parse_prediction_output(output: str):
    details = {
        "actual_type": "Unknown",
        "prediction": "Unknown",
        "is_anomaly": None,
        "sample_features": []
    }

    for line in output.splitlines():
        cleaned = line.strip()
        if cleaned.startswith("- ") and ":" in cleaned:
            name, value = cleaned[2:].split(":", 1)
            details["sample_features"].append({
                "name": name.strip(),
                "value": value.strip()
            })
        elif cleaned.startswith("Actual Type"):
            details["actual_type"] = cleaned.split(":", 1)[1].strip()
        elif cleaned.startswith("Model Prediction"):
            prediction = cleaned.split(":", 1)[1].strip()
            details["prediction"] = prediction
            details["is_anomaly"] = "Anomalous" in prediction

    return details

@app.get("/", response_class=HTMLResponse)
def home():
    return """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Network Anomaly Detection</title>
  <style>
    :root {
      color-scheme: light;
      --ink: #18202f;
      --muted: #667085;
      --line: #d9dee8;
      --panel: #ffffff;
      --soft: #f4f7fb;
      --brand: #0f766e;
      --brand-dark: #115e59;
      --danger: #c2410c;
      --danger-soft: #fff3ed;
      --safe: #15803d;
      --safe-soft: #edfdf3;
    }

    * { box-sizing: border-box; }

    body {
      margin: 0;
      min-height: 100vh;
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      color: var(--ink);
      background:
        linear-gradient(135deg, rgba(15, 118, 110, 0.10), transparent 34%),
        linear-gradient(315deg, rgba(37, 99, 235, 0.10), transparent 38%),
        var(--soft);
    }

    main {
      width: min(1120px, calc(100% - 32px));
      margin: 0 auto;
      padding: 44px 0;
    }

    .hero {
      display: grid;
      grid-template-columns: minmax(0, 1.25fr) minmax(300px, 0.75fr);
      gap: 24px;
      align-items: stretch;
      margin-bottom: 24px;
    }

    .intro, .panel, .result {
      background: rgba(255, 255, 255, 0.92);
      border: 1px solid rgba(217, 222, 232, 0.9);
      border-radius: 8px;
      box-shadow: 0 20px 45px rgba(24, 32, 47, 0.08);
    }

    .intro {
      padding: 32px;
      display: flex;
      flex-direction: column;
      justify-content: center;
    }

    .eyebrow {
      margin: 0 0 10px;
      color: var(--brand-dark);
      font-size: 0.78rem;
      font-weight: 800;
      letter-spacing: 0.08em;
      text-transform: uppercase;
    }

    h1 {
      margin: 0;
      max-width: 760px;
      font-size: clamp(2rem, 5vw, 4.2rem);
      line-height: 0.98;
      letter-spacing: 0;
    }

    .intro p {
      max-width: 690px;
      margin: 18px 0 0;
      color: var(--muted);
      font-size: 1.05rem;
      line-height: 1.65;
    }

    .panel {
      padding: 24px;
      display: grid;
      gap: 18px;
      align-content: center;
    }

    label {
      display: block;
      margin-bottom: 8px;
      color: #344054;
      font-weight: 700;
      font-size: 0.92rem;
    }

    input[type="file"] {
      width: 100%;
      padding: 13px;
      border: 1px dashed #aab4c3;
      border-radius: 8px;
      background: #fbfcfe;
      color: var(--muted);
    }

    .actions {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 10px;
    }

    button {
      min-height: 44px;
      border: 0;
      border-radius: 8px;
      padding: 0 16px;
      background: var(--brand);
      color: white;
      font-weight: 800;
      cursor: pointer;
      transition: transform 140ms ease, background 140ms ease;
    }

    button.secondary {
      background: #263244;
    }

    button:hover { transform: translateY(-1px); background: var(--brand-dark); }
    button.secondary:hover { background: #111827; }
    button:disabled { cursor: wait; opacity: 0.7; transform: none; }

    .status {
      min-height: 22px;
      color: var(--muted);
      font-size: 0.92rem;
    }

    .result {
      display: none;
      overflow: hidden;
    }

    .result.show { display: block; }

    .result-head {
      display: flex;
      justify-content: space-between;
      gap: 16px;
      padding: 24px;
      border-bottom: 1px solid var(--line);
      background: #fff;
    }

    .badge {
      align-self: flex-start;
      white-space: nowrap;
      border-radius: 999px;
      padding: 8px 12px;
      font-weight: 900;
      font-size: 0.86rem;
    }

    .badge.safe { color: var(--safe); background: var(--safe-soft); }
    .badge.danger { color: var(--danger); background: var(--danger-soft); }

    h2 {
      margin: 0;
      font-size: clamp(1.45rem, 3vw, 2.4rem);
      letter-spacing: 0;
    }

    .meta {
      margin: 8px 0 0;
      color: var(--muted);
    }

    .grid {
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 1px;
      background: var(--line);
    }

    .metric {
      min-height: 112px;
      padding: 20px;
      background: #fff;
    }

    .metric span {
      display: block;
      margin-bottom: 8px;
      color: var(--muted);
      font-size: 0.78rem;
      font-weight: 800;
      letter-spacing: 0.08em;
      text-transform: uppercase;
    }

    .metric strong {
      overflow-wrap: anywhere;
      font-size: 1.05rem;
    }

    pre {
      margin: 0;
      max-height: 320px;
      overflow: auto;
      padding: 22px 24px;
      background: #101828;
      color: #e4edf7;
      font-size: 0.9rem;
      line-height: 1.55;
      white-space: pre-wrap;
    }

    @media (max-width: 820px) {
      main { padding-top: 24px; }
      .hero, .grid { grid-template-columns: 1fr; }
      .intro { padding: 24px; }
      .actions { grid-template-columns: 1fr; }
      .result-head { flex-direction: column; }
      .badge { align-self: flex-start; }
    }
  </style>
</head>
<body>
  <main>
    <section class="hero">
      <div class="intro">
        <p class="eyebrow">Major Project</p>
        <h1>Network Anomaly Detection</h1>
        <p>Upload a CSV dataset, run the trained model, and view the sampled flow prediction in a clean dashboard.</p>
      </div>

      <form class="panel" id="upload-form">
        <div>
          <label for="dataset">CSV dataset</label>
          <input id="dataset" name="file" type="file" accept=".csv" required>
        </div>
        <div class="actions">
          <button type="submit">Upload CSV</button>
          <button class="secondary" id="predict-btn" type="button">Run Prediction</button>
        </div>
        <div class="status" id="status">Ready.</div>
      </form>
    </section>

    <section class="result" id="result">
      <div class="result-head">
        <div>
          <h2 id="result-title">Prediction result</h2>
          <p class="meta" id="result-meta"></p>
        </div>
        <div class="badge" id="result-badge">Waiting</div>
      </div>
      <div class="grid">
        <div class="metric">
          <span>Actual type</span>
          <strong id="actual-type">Unknown</strong>
        </div>
        <div class="metric">
          <span>Model prediction</span>
          <strong id="prediction">Unknown</strong>
        </div>
        <div class="metric">
          <span>Sampled features</span>
          <strong id="features">None yet</strong>
        </div>
      </div>
      <pre id="raw-output"></pre>
    </section>
  </main>

  <script>
    const form = document.getElementById("upload-form");
    const statusEl = document.getElementById("status");
    const predictBtn = document.getElementById("predict-btn");
    const result = document.getElementById("result");
    const badge = document.getElementById("result-badge");

    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      const file = document.getElementById("dataset").files[0];
      if (!file) return;

      statusEl.textContent = "Uploading dataset...";
      const data = new FormData();
      data.append("file", file);

      const response = await fetch("/api/upload", { method: "POST", body: data });
      const json = await response.json();
      statusEl.textContent = json.error || json.message || "Upload complete.";
    });

    predictBtn.addEventListener("click", async () => {
      predictBtn.disabled = true;
      statusEl.textContent = "Running model prediction...";

      try {
        const response = await fetch("/api/predict", { method: "POST" });
        const json = await response.json();

        if (json.error) {
          statusEl.textContent = json.error;
          return;
        }

        const details = json.details || {};
        const isAnomaly = details.is_anomaly === true;
        const isSafe = details.is_anomaly === false;
        const features = (details.sample_features || [])
          .map((item) => `${item.name}: ${item.value}`)
          .join("\\n");

        result.classList.add("show");
        document.getElementById("result-title").textContent = isAnomaly
          ? "Anomalous traffic detected"
          : isSafe
            ? "Normal traffic detected"
            : "Prediction complete";
        document.getElementById("result-meta").textContent = "The dashboard below is generated from the latest model run.";
        document.getElementById("actual-type").textContent = details.actual_type || "Unknown";
        document.getElementById("prediction").textContent = details.prediction || "Unknown";
        document.getElementById("features").textContent = features || "No sampled feature preview returned.";
        document.getElementById("raw-output").textContent = json.output || "";

        badge.className = `badge ${isAnomaly ? "danger" : "safe"}`;
        badge.textContent = isAnomaly ? "Anomaly" : isSafe ? "Normal" : "Complete";
        statusEl.textContent = "Prediction finished.";
        result.scrollIntoView({ behavior: "smooth", block: "start" });
      } catch (error) {
        statusEl.textContent = `Prediction failed: ${error.message}`;
      } finally {
        predictBtn.disabled = false;
      }
    });
  </script>
</body>
</html>
    """

@app.on_event("startup")
def startup_event():
    load_dataset()

@app.get("/api/dataset")
def get_dataset(page: int = 1, page_size: int = 15):
    global dataset_df
    if dataset_df is None:
        return {"error": "Dataset not found", "columns": [], "rows": [], "total_rows": 0}
    
    total_rows = len(dataset_df)
    total_pages = (total_rows + page_size - 1) // page_size
    
    start_idx = (page - 1) * page_size
    end_idx = start_idx + page_size
    
    chunk = dataset_df.iloc[start_idx:end_idx]
    
    # Convert to dict
    columns = list(chunk.columns)
    rows = chunk.values.tolist()
    
    return {
        "columns": columns,
        "rows": rows,
        "total_rows": total_rows,
        "total_pages": total_pages,
        "page": page,
        "page_size": page_size
    }

@app.get("/api/graph")
def get_graph():
    if not os.path.exists(GRAPH_IMG_PATH):
        # Generate the graph if it doesn't exist
        try:
            import visualize_graph
            visualize_graph.visualize()
        except Exception as e:
            return {"error": f"Failed to generate graph: {e}"}
            
    if os.path.exists(GRAPH_IMG_PATH):
        return FileResponse(GRAPH_IMG_PATH, media_type="image/png")
    return {"error": "Graph image not found"}

@app.post("/api/upload")
async def upload_dataset(file: UploadFile = File(...)):
    # Save the uploaded file
    os.makedirs("data", exist_ok=True)
    with open(UPLOAD_PATH, "wb") as f:
        content = await file.read()
        f.write(content)
        
    return {"message": "File uploaded successfully", "filename": file.filename}

@app.post("/api/predict")
def run_prediction():
    if not os.path.exists(UPLOAD_PATH):
        return {"error": "No dataset uploaded yet. Please upload a CSV first."}
        
    # Run predict.py
    try:
        python_executable = os.path.join("venv", "Scripts", "python.exe")
        if not os.path.exists(python_executable):
            python_executable = sys.executable

        result = subprocess.run(
            [python_executable, "predict.py", "--data", UPLOAD_PATH],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace"
        )
        return {
            "output": result.stdout,
            "error_output": result.stderr,
            "return_code": result.returncode,
            "details": parse_prediction_output(result.stdout)
        }
    except Exception as e:
        return {"error": str(e)}

if __name__ == "__main__":
    import uvicorn
    threading.Timer(1.2, lambda: webbrowser.open("http://127.0.0.1:8000")).start()
    uvicorn.run(app, host="0.0.0.0", port=8000)
