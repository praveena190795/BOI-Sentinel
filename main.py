import os
import subprocess
import requests
import json
import time
import threading
import hashlib
import shutil
from typing import List, Dict, Tuple, Any
from fastapi import FastAPI, HTTPException, UploadFile, File
import uvicorn
from scapy.all import sniff, IP, TCP, UDP
from fastapi.responses import PlainTextResponse
from langchain_google_genai import ChatGoogleGenerativeAI
from langgraph.graph import StateGraph, END

# Import your custom local state definitions
from state import AnalysisState
from dynamic_ml_node import dynamic_ml_node

app = FastAPI(title="GenAI Automated Reverse Engineering Platform")

# Configuration Constants
MOBSF_URL = "http://localhost:8000"
MOBSF_API_KEY = "9d0465944cf8a606c30aa07aa0a74a1659c05df7f213ab731400a5fc1e31899a"
UPLOAD_DIR = "./local_storage"

# In-memory dictionary to store processed intelligence reports
KNOWN_HASHES = {}

os.makedirs(UPLOAD_DIR, exist_ok=True)

# Initialize your LangGraph framework builder
workflow = StateGraph(AnalysisState)


# =====================================================================
# INTERNAL PIPELINE HELPER FUNCTIONS 
# =====================================================================

def save_uploaded_apk(file: UploadFile) -> str:
    file_path = os.path.join(UPLOAD_DIR, file.filename if file.filename else "target.apk")
    try:
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
    finally:
        file.file.close()
    return file_path

def calculate_sha256(file_path: str) -> str:
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    return sha256.hexdigest()

def _analyze_static(file_path: str) -> dict:
    if not os.path.exists(file_path):
        raise HTTPException(status_code=400, detail="Target APK file path does not exist.")

    headers = {"Authorization": MOBSF_API_KEY}
    
    with open(file_path, "rb") as apk_file:
        files = {"file": (os.path.basename(file_path), apk_file, "application/octet-stream")}
        print(f"Uploading {file_path} to MobSF Container...")
        upload_response = requests.post(f"{MOBSF_URL}/api/v1/upload", files=files, headers=headers)
    
    if upload_response.status_code != 200:
        raise HTTPException(status_code=500, detail=f"MobSF upload failed: {upload_response.text}")

    upload_data = upload_response.json()
    mobsf_hash = upload_data.get("hash")

    print(f"Triggering static analysis scanning for hash: {mobsf_hash}...")
    scan_payload = {"hash": mobsf_hash}
    scan_response = requests.post(f"{MOBSF_URL}/api/v1/scan", data=scan_payload, headers=headers)

    if scan_response.status_code != 200:
         raise HTTPException(status_code=500, detail="MobSF analysis phase failed.")

    report_payload = {"hash": mobsf_hash}
    report_response = requests.post(f"{MOBSF_URL}/api/v1/report_json", data=report_payload, headers=headers)

    try:
        return report_response.json()
    except Exception:
        return {"error": "Failed to parse json response from MobSF", "raw_text": report_response.text}


def _calculate_metrics(static_data: Any, dynamic_logs: str) -> Tuple[int, int, Dict[str, bool]]:
    INDICATORS = {
        "accessibility_abuse": 30,
        "sms_read": 25,
        "overlay_permission": 20,
        "credential_harvesting_strings": 20,
        "known_malicious_url": 25,
        "runtime_c2_connection": 35,
        "dynamic_code_loading": 30,
        "banking_keywords": 15,
    }

    detected = {k: False for k in INDICATORS.keys()}
    if not isinstance(static_data, dict):
        return 0, 0, detected

    permissions = static_data.get("permissions", {})
    if not isinstance(permissions, dict):
        permissions = {}

    try:
        findings_str = json.dumps(static_data.get("high_vulnerabilities", [])).lower()
    except Exception:
        findings_str = ""

    urls_list = [u.get("url", "") for u in static_data.get("extracted_urls", []) if isinstance(u, dict)]
    logs_lower = str(dynamic_logs).lower()

    if "android.permission.BIND_ACCESSIBILITY_SERVICE" in permissions:
        detected["accessibility_abuse"] = True
    if any(p in permissions for p in ["android.permission.READ_SMS", "android.permission.RECEIVE_SMS"]):
        detected["sms_read"] = True
    if "android.permission.SYSTEM_ALERT_WINDOW" in permissions:
        detected["overlay_permission"] = True

    if any(k in findings_str for k in ["dexclassloader", "pathclassloader", "dalvik.system"]):
        detected["dynamic_code_loading"] = True
    if any(k in findings_str or k in logs_lower for k in ["login", "webview", "credential", "password", "auth"]):
        detected["credential_harvesting_strings"] = True
    if any(k in findings_str or k in logs_lower for k in ["banking", "bank", "otp", "transfer", "crypto"]):
        detected["banking_keywords"] = True

    if "outbound_connection ->" in dynamic_logs:
        detected["runtime_c2_connection"] = True

    for url in urls_list:
        if any(bad in url.lower() for bad in ["evil", "malw", "c2", "ngrok", "freecluster"]):
            detected["known_malicious_url"] = True

    has_static = len(permissions) > 0 or len(static_data.get("high_vulnerabilities", [])) > 0
    has_dynamic = "outbound_connection ->" in dynamic_logs or len(logs_lower) > 200
    
    correlates = False
    if detected["runtime_c2_connection"] and len(urls_list) > 0:
        correlates = True
    if detected["accessibility_abuse"] and detected["overlay_permission"]:
        correlates = True

    c_score = 0
    if has_static: c_score += 20
    if has_dynamic: c_score += 30
    if correlates: c_score += 20
    if detected["known_malicious_url"]: c_score += 30
    confidence = min(c_score, 100)

    calculated_risk = 0
    confidence_factor = confidence / 100.0
    for indicator, weight in INDICATORS.items():
        if detected[indicator]:
            calculated_risk += weight * confidence_factor

    risk_score = min(100, round(calculated_risk))
    return risk_score, confidence, detected


# =====================================================================
# LANGGRAPH AGENT NODES
# =====================================================================

def sanitize_static_node(state: AnalysisState) -> Dict[str, Any]:
    print("\n[Agent 1] Filtering and sanitizing static JSON data...")
    raw_data = state.get("raw_static_json", {})
    
    if isinstance(raw_data, str):
        try:
            raw_data = json.loads(raw_data)
        except Exception:
            raw_data = {}

    if not isinstance(raw_data, dict):
        raw_data = {}
    
    sanitized = {
        "permissions": raw_data.get("permissions", {}),
        "high_vulnerabilities": [v for v in raw_data.get("code_analysis", {}).get("findings", []) if isinstance(v, dict) and v.get("severity") == "high"],
        "extracted_urls": raw_data.get("urls", []),
        "trackers": raw_data.get("trackers", {}).get("trackers", [])
    }
    return {"filtered_static_data": sanitized}


def run_dynamic_analysis_node(state: AnalysisState) -> Dict[str, Any]:
    package_name = state.get("package_name", "unknown.package")
    apk_path = state.get("apk_path", "")
    print(f"\n[Agent 2] STARTING REAL RUNTIME DYNAMIC ANALYSIS FOR: {package_name}...")

    captured_packets = []
    def packet_callback(packet):
        if packet.haslayer(IP):
            dest_ip = packet[IP].dst
            if packet.haslayer(TCP):
                captured_packets.append(f" outbound_connection -> IP: {dest_ip} (TCP Port: {packet[TCP].dport})")
            elif packet.haslayer(UDP):
                captured_packets.append(f" outbound_connection -> IP: {dest_ip} (UDP Port: {packet[UDP].dport})")

    def internal_sniff():
        try:
            sniff(prn=packet_callback, count=30, timeout=8, store=0)
        except Exception as sniff_err:
            captured_packets.append(f"Sniffer execution warning: {str(sniff_err)}")

    sniffer_thread = threading.Thread(target=internal_sniff)
    sniffer_thread.start()

    log_summary = ""
    try:
        subprocess.run(["adb", "logcat", "-c"], check=True)
        print(f" -> Installing {package_name} onto sandbox device...")
        subprocess.run(["adb", "install", "-r", apk_path], check=True)
        
        print(f" -> Launching {package_name} main screen activity...")
        launch_cmd = f"adb shell monkey -p {package_name} -c android.intent.category.LAUNCHER 1"
        subprocess.run(launch_cmd.split(), check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        print(" -> Injecting 50 simulated user interactions...")
        stress_cmd = f"adb shell monkey -p {package_name} 50"
        subprocess.run(stress_cmd.split(), check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        time.sleep(4)
        raw_logs = subprocess.check_output(["adb", "logcat", "-d"]).decode(errors="ignore")
        
        filtered_lines = []
        for line in raw_logs.split("\n"):
            if any(keyword in line.lower() for keyword in ["error", "exception", "http", "socket", "connect"]):
                filtered_lines.append(line.strip())
        log_summary = "\n".join(filtered_lines[:15])  # Keeps token footprint minimal

    except Exception as e:
        print(f"[!] Target device automation interaction error: {str(e)}")
        log_summary = f"Dynamic interaction phase hit an execution failure: {str(e)}"

    try:
        sniffer_thread.join(timeout=10)
    except Exception:
        pass

    network_summary = "\n".join(set(captured_packets)) if captured_packets else "No unique network packets captured."
    compiled_dynamic_report = f"\n=== AUTOMATED DYNAMIC RUNTIME LOGS ===\n{log_summary}\n\n=== LIVE CAPTURED NETWORK CONNECTIONS ===\n{network_summary}\n"
    
    return {"dynamic_log_data": str(compiled_dynamic_report)}


def generate_threat_report_node(state: AnalysisState) -> Dict[str, Any]:
    print("\n[Agent 3] Deploying 'BOI Sentinel' Threat Intelligence Engine...")
    package_name = state.get("package_name")
    static_context = state.get("filtered_static_data", {})
    dynamic_context = state.get("dynamic_log_data", "")
    ml_prediction = state.get("dynamic_ml_prediction", "Unknown")
    ml_confidence = state.get("dynamic_ml_confidence", 0)
    
    try:
        risk_score, confidence, indicators = _calculate_metrics(static_context, dynamic_context)
    except Exception as calc_err:
        print(f"[!] Math/Metric Engine failure: {str(calc_err)}")
        risk_score, confidence = 0, 0 

    try:
        llm = ChatGoogleGenerativeAI(model="gemini-2.5-flash", temperature=0.0, max_retries=3)
        
       
        system_role = """You are "BOI Sentinel", an elite Android Malware Reverse Engineer. Create structural intelligence reports."""
        package_name = state.get("package_name")
        static_context = state.get("filtered_static_data", {})
        dynamic_context = state.get("dynamic_log_data", "")
        ml_prediction = state.get("dynamic_ml_prediction", "Unknown")
        ml_confidence = state.get("dynamic_ml_confidence", 0)
        user_prompt = f"""
        TARGET APK UNDER ANALYSIS: {package_name}
        Calculated Risk Score: {risk_score}
        Calculated Confidence: {confidence}%

        ML Malware Classification:
        Category: {ml_prediction}
        Confidence: {ml_confidence}%  

        EVIDENCE BUNDLE 1: {json.dumps(static_context)}
        EVIDENCE BUNDLE 2: {dynamic_context}
        
        Generate the report matching client specifications perfectly.
        """
        response = llm.invoke([
            ("system", system_role),
            ("human", user_prompt)
        ])
        return {
            "final_report_markdown": str(response.content),
            "risk_score": int(risk_score)
        }
    except Exception as e:
        fallback_str = f"APK THREAT ASSESSMENT REPORT (ERROR FALLBACK)\nScore: {risk_score}\nException: {str(e)}"
        return {
            "final_report_markdown": fallback_str,
            "risk_score": int(risk_score)
        }


# =====================================================================
# FRAMEWORK GRAPH COMPILATION
# =====================================================================


workflow.add_node("dynamic_ml", dynamic_ml_node)
workflow.add_node("sanitize_static", sanitize_static_node)
workflow.add_node("run_dynamic", run_dynamic_analysis_node)
workflow.add_node("generate_report", generate_threat_report_node)

workflow.set_entry_point("sanitize_static")

workflow.add_edge("sanitize_static", "run_dynamic")
workflow.add_edge("run_dynamic", "dynamic_ml")
workflow.add_edge("dynamic_ml", "generate_report")
workflow.add_edge("generate_report", END)

app_pipeline = workflow.compile()


# =====================================================================
# FASTAPI ENDPOINTS
# =====================================================================

@app.post("/auto-pipeline/", response_class=PlainTextResponse)
def run_entire_pipeline(file: UploadFile = File(...)):
    try:
        local_file_path = save_uploaded_apk(file)
        apk_hash = calculate_sha256(local_file_path)
        
        # -------------------------------------------------------------
        # OUTPUT STATE 3: DUPLICATE DETECTION CACHE LOOKUP
        # -------------------------------------------------------------
        if apk_hash in KNOWN_HASHES:
            return f"""====================================================
PREVIOUSLY ANALYZED APK DETECTED
====================================================

Hash:
{apk_hash}

Returning Stored Threat Intelligence Report

{KNOWN_HASHES[apk_hash]["full_report"]}"""

        mobsf_raw_json = _analyze_static(local_file_path)
        package_name = mobsf_raw_json.get("package_name", "unknown.package")

        score = 0
        permissions = mobsf_raw_json.get("permissions", {})
        if "android.permission.READ_SMS" in permissions: score += 25
        if "android.permission.RECEIVE_SMS" in permissions: score += 25
        if "android.permission.SYSTEM_ALERT_WINDOW" in permissions: score += 20
        if "android.permission.BIND_ACCESSIBILITY_SERVICE" in permissions: score += 30

        # -------------------------------------------------------------
        # OUTPUT STATE 1 & 2: THRESHOLD RULES FOR DEEP PROCESSING
        # -------------------------------------------------------------
        # Toggle this threshold target as needed for your tests:
        # Use 'score < 30' for selective testing. 
        # Use 'score < 0' to deliberately force ALL apps through full analysis.
        if score < 0:
            return f"LOW RISK APK\nPackage: {package_name}\nMetadata Risk: {score}\nNo deep analysis required."
        
        if isinstance(mobsf_raw_json, str):
            try:
                mobsf_raw_json = json.loads(mobsf_raw_json)
            except Exception:
                raise HTTPException(status_code=500, detail="MobSF payload was unparseable text string.")

        initial_inputs = {
            "apk_path": str(local_file_path),
            "package_name": str(package_name),
            "apk_hash": apk_hash,
            "metadata_score": score,
            "known_malware": False,
            "raw_static_json": mobsf_raw_json,
            "filtered_static_data": {},
            "dynamic_log_data": "",
            "mitre_mappings": [],
            "risk_score": 0,
            "verdict_justification": "",
            "final_report_markdown": "",
            "dynamic_ml_prediction": "",
            "dynamic_ml_confidence": 0.0,
        }
        
        final_graph_output = app_pipeline.invoke(initial_inputs)
        report_output = final_graph_output["final_report_markdown"]
        
        # Only cache the report if it generated cleanly without hitting the API fallback string
        if "ERROR FALLBACK" not in report_output:
            KNOWN_HASHES[apk_hash] = {"full_report": report_output}
            
        return report_output
        
    except Exception as global_exc:
        raise HTTPException(status_code=500, detail=f"Pipeline Execution Broken: {str(global_exc)}")


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8080, reload=True)