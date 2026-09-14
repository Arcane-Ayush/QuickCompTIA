"""Standalone Python HTTP server serving Dashboard UI and pipeline REST API endpoints."""

import os
import json
import sys
import argparse
from http.server import HTTPServer, SimpleHTTPRequestHandler
from typing import Dict, Any


def load_json(file_path: str) -> Dict[str, Any]:
    """Load JSON file content or return empty dictionary fallback if file not found."""
    if os.path.exists(file_path):
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {}


class DashboardHTTPRequestHandler(SimpleHTTPRequestHandler):
    """HTTP Request Handler serving dashboard static web assets and REST API endpoints."""

    def __init__(self, *args, **kwargs) -> None:
        """Initialize handler setting root static directory to dashboard_ui folder."""
        dashboard_dir = os.path.dirname(os.path.abspath(__file__))
        super().__init__(*args, directory=dashboard_dir, **kwargs)

    def do_GET(self) -> None:
        """Handle GET requests for static files and /api/data endpoint."""
        if self.path == "/api/data":
            self.handle_api_data()
        elif self.path in ["/graph_export.json", "/findings.json", "/remediations.json"]:
            self.handle_root_file(self.path.strip("/"))
        else:
            super().do_GET()

    def do_POST(self) -> None:
        """Handle POST requests for /api/run-pipeline execution endpoint."""
        if self.path == "/api/run-pipeline":
            self.handle_api_run_pipeline()
        else:
            self.send_error(404, "Endpoint not found")

    def handle_api_data(self) -> None:
        """Serve combined JSON containing graph, findings, and remediations datasets."""
        root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        
        graph = load_json(os.path.join(root_dir, "graph_export.json"))
        findings = load_json(os.path.join(root_dir, "findings.json"))
        remediations = load_json(os.path.join(root_dir, "remediations.json"))

        # Fallback to module-internal samples if root files do not exist
        if not findings:
            findings = load_json(os.path.join(root_dir, "detection_engine", "findings.json"))
        if not remediations:
            remediations = load_json(os.path.join(root_dir, "remediation_generator", "remediations.json"))

        response_payload = {
            "graph": graph,
            "findings": findings,
            "remediations": remediations
        }

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps(response_payload).encode("utf-8"))

    def handle_root_file(self, filename: str) -> None:
        """Serve root JSON files to dashboard client."""
        root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        file_path = os.path.join(root_dir, filename)
        
        if os.path.exists(file_path):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            with open(file_path, "rb") as f:
                self.wfile.write(f.read())
        else:
            self.send_error(404, f"File {filename} not found")

    def handle_api_run_pipeline(self) -> None:
        """Execute full 4-stage pipeline end-to-end via Python call."""
        root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        sys.path.insert(0, root_dir)
        
        try:
            from parser_graph.main import run as run_parser
            from detection_engine.detector import run_detection
            from remediation_generator.generator import RemediationGenerator

            sample_input = os.path.join(root_dir, "sample_data", "iam_export_sample.json")
            graph_out = os.path.join(root_dir, "graph_export.json")
            findings_out = os.path.join(root_dir, "findings.json")
            remediations_out = os.path.join(root_dir, "remediations.json")

            run_parser(sample_input, graph_out)
            run_detection(graph_out, findings_out)

            with open(findings_out, "r", encoding="utf-8") as f:
                findings_data = json.load(f)
            generator = RemediationGenerator()
            rem_data = generator.generate_remediations(findings_data)

            with open(remediations_out, "w", encoding="utf-8") as f:
                json.dump(rem_data, f, indent=2)

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"status": "success", "message": "Pipeline re-run successfully."}).encode("utf-8"))
        except Exception as e:
            self.send_response(500)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"status": "error", "message": str(e)}).encode("utf-8"))


def start_server(port: int = 8080, host: str = "0.0.0.0") -> None:
    """Start the dashboard HTTP web server on specified host and port."""
    server_address = (host, port)
    httpd = HTTPServer(server_address, DashboardHTTPRequestHandler)
    print(f"[Person 4 - Dashboard UI] Server running at http://localhost:{port}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[Person 4 - Dashboard UI] Server stopped.")
        httpd.server_close()


def main() -> None:
    """Parse arguments and start server CLI."""
    parser = argparse.ArgumentParser(description="CLOUD IAM MISCONFIGURATION DETECTOR - Dashboard Server")
    parser.add_argument("--port", "-p", type=int, default=8080, help="Port to run web server on (default: 8080)")
    parser.add_argument("--host", default="0.0.0.0", help="Host interface (default: 0.0.0.0)")
    args = parser.parse_args()

    start_server(port=args.port, host=args.host)


if __name__ == "__main__":
    main()
