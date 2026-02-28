from __future__ import annotations

from flask import Blueprint, current_app, jsonify, request

from app.core.attacker_service import AttackerService
from app.core.defender_service import DefenderService
from app.core.system_service import SystemService

api_bp = Blueprint("api", __name__, url_prefix="/api")


def _services() -> tuple[AttackerService, DefenderService, SystemService]:
    state = current_app.config["STATE"]
    attacker = AttackerService(state)
    defender = DefenderService(state)
    system = SystemService(attacker=attacker, defender=defender, state=state)
    return attacker, defender, system


@api_bp.get("/status")
def attack_status():
    attacker, _, _ = _services()
    return jsonify(attacker.get_status())


@api_bp.get("/logs")
def attack_logs():
    attacker, _, _ = _services()
    limit = request.args.get("limit", 50, type=int)
    return jsonify(attacker.get_logs(limit=max(1, limit)))


@api_bp.get("/interfaces")
def interfaces():
    attacker, _, _ = _services()
    return jsonify(attacker.get_interfaces())


@api_bp.post("/start")
def start_attack():
    attacker, _, _ = _services()
    body = request.get_json(silent=True) or {}
    payload, status = attacker.start(body)
    return jsonify(payload), status


@api_bp.post("/stop")
def stop_attack():
    attacker, _, _ = _services()
    payload, status = attacker.stop()
    return jsonify(payload), status


@api_bp.get("/defender/status")
def defender_status():
    _, defender, _ = _services()
    return jsonify(defender.status())


@api_bp.get("/defender/alerts")
def defender_alerts():
    _, defender, _ = _services()
    limit = request.args.get("limit", 50, type=int)
    return jsonify(defender.alerts(limit=max(1, limit)))


@api_bp.get("/defender/flagged")
def defender_flagged():
    _, defender, _ = _services()
    return jsonify(defender.flagged())


@api_bp.post("/defender/start")
def defender_start():
    _, defender, _ = _services()
    body = request.get_json(silent=True) or {}
    payload, status = defender.start(body)
    return jsonify(payload), status


@api_bp.post("/defender/stop")
def defender_stop():
    _, defender, _ = _services()
    payload, status = defender.stop()
    return jsonify(payload), status


@api_bp.post("/defender/unflag")
def defender_unflag():
    _, defender, _ = _services()
    body = request.get_json(silent=True) or {}
    payload, status = defender.unflag(body)
    return jsonify(payload), status


@api_bp.post("/defender/clear_flags")
def defender_clear_flags():
    _, defender, _ = _services()
    payload, status = defender.clear_flags()
    return jsonify(payload), status


@api_bp.post("/minimize")
def minimize():
    _, _, system = _services()
    payload, status = system.minimize()
    return jsonify(payload), status


@api_bp.post("/shutdown")
def shutdown():
    _, _, system = _services()
    payload, status = system.shutdown()
    return jsonify(payload), status
