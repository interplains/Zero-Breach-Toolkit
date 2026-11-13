#!/usr/bin/env python3
"""Minimal copy-trading bot prototype.

This script copies trades from configured leaderboard accounts into a follower account.
It is intentionally lightweight and safe: the default mode is a dry-run/paper trading
simulation, which means no network calls or live exchange operations are performed.

Example:
    python copy_trade_bot.py --config sample_copy_trade_config.json --signals sample_copy_trade_signals.json
"""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Sequence


VALID_SIDES = {"buy", "sell"}


@dataclass
class Signal:
    leader: str
    symbol: str
    side: str
    quantity: float
    price: float
    confidence: float
    timestamp: str = ""

    @classmethod
    def from_dict(cls, payload: Dict[str, Any]) -> "Signal":
        try:
            signal = cls(
                leader=str(payload["leader"]).strip(),
                symbol=str(payload["symbol"]).strip().upper(),
                side=str(payload["side"]).strip().lower(),
                quantity=float(payload["quantity"]),
                price=float(payload["price"]),
                confidence=float(payload.get("confidence", 0.0)),
                timestamp=str(payload.get("timestamp", "")),
            )
        except (KeyError, TypeError, ValueError) as exc:  # pragma: no cover - defensive
            raise ValueError(f"Invalid signal payload: {payload!r}") from exc

        if signal.side not in VALID_SIDES:
            raise ValueError(f"Invalid trade side '{signal.side}' for {signal.symbol!r}")
        if signal.quantity <= 0 or signal.price <= 0:
            raise ValueError(f"Invalid trade quantity/price for {signal.symbol!r}")
        if not 0.0 <= signal.confidence <= 1.0:
            raise ValueError(f"Confidence must be between 0 and 1 for {signal.symbol!r}")
        return signal


@dataclass
class BotConfig:
    leaders: list[str]
    min_confidence: float = 0.7
    max_position_value: float = 10_000.0
    risk_per_trade: float = 0.02
    account_cash: float = 50_000.0
    dry_run: bool = True

    @classmethod
    def from_dict(cls, payload: Dict[str, Any]) -> "BotConfig":
        leaders = payload.get("leaders") or payload.get("leader_names") or []
        if not isinstance(leaders, list) or not leaders:
            raise ValueError("Bot config must include at least one leader name")

        config = cls(
            leaders=[str(item).strip() for item in leaders if str(item).strip()],
            min_confidence=float(payload.get("min_confidence", 0.7)),
            max_position_value=float(payload.get("max_position_value", 10_000.0)),
            risk_per_trade=float(payload.get("risk_per_trade", 0.02)),
            account_cash=float(payload.get("account_cash", 50_000.0)),
            dry_run=bool(payload.get("dry_run", True)),
        )
        if not 0.0 <= config.min_confidence <= 1.0:
            raise ValueError("min_confidence must be between 0 and 1")
        if config.max_position_value <= 0:
            raise ValueError("max_position_value must be positive")
        if not 0.0 < config.risk_per_trade <= 1.0:
            raise ValueError("risk_per_trade must be between 0 and 1")
        if config.account_cash <= 0:
            raise ValueError("account_cash must be positive")
        return config


def load_json(path: str | Path) -> Any:
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def load_signals(path: str | Path) -> List[Signal]:
    payload = load_json(path)
    if isinstance(payload, dict):
        items = payload.get("signals") or payload.get("trades") or payload.get("data") or []
    elif isinstance(payload, list):
        items = payload
    else:
        raise ValueError("Signal feed must be a list of trade objects or a JSON object with a 'signals' list")

    signals = []
    for item in items:
        if not isinstance(item, dict):
            raise ValueError(f"Signal entry must be an object: {item!r}")
        signals.append(Signal.from_dict(item))
    return signals


def load_config(path: str | Path) -> BotConfig:
    payload = load_json(path)
    if not isinstance(payload, dict):
        raise ValueError("Config file must contain a JSON object")
    return BotConfig.from_dict(payload)


def _copy_limit(bot_config: BotConfig, signal: Signal) -> float:
    max_trade_value = bot_config.max_position_value
    cash_cap = bot_config.account_cash * bot_config.risk_per_trade
    return min(max_trade_value, cash_cap)


def run_copy_trading(signals: Iterable[Signal], config: BotConfig) -> Dict[str, Any]:
    allowed_leaders = {leader.lower() for leader in config.leaders}
    positions: Dict[str, float] = {}
    cash = config.account_cash
    executed: List[Dict[str, Any]] = []

    for signal in signals:
        if signal.leader.lower() not in allowed_leaders:
            continue
        if signal.confidence < config.min_confidence:
            continue

        trade_value = signal.quantity * signal.price
        if trade_value <= 0:
            continue

        max_trade_value = _copy_limit(config, signal)
        normalized_trade_value = min(trade_value, max_trade_value)

        if signal.side == "buy":
            if cash < normalized_trade_value:
                normalized_trade_value = cash
            if normalized_trade_value <= 0:
                continue
            copied_quantity = normalized_trade_value / signal.price
            cash -= normalized_trade_value
            positions[signal.symbol] = positions.get(signal.symbol, 0.0) + copied_quantity
        else:
            available = positions.get(signal.symbol, 0.0)
            if available <= 0:
                continue
            copied_quantity = min(available, signal.quantity)
            normalized_trade_value = copied_quantity * signal.price
            cash += normalized_trade_value
            positions[signal.symbol] = available - copied_quantity
            if positions[signal.symbol] <= 0:
                positions.pop(signal.symbol, None)

        order = {
            "leader": signal.leader,
            "symbol": signal.symbol,
            "side": signal.side,
            "quantity": round(copied_quantity, 8),
            "value": round(normalized_trade_value, 2),
            "price": signal.price,
            "confidence": signal.confidence,
            "timestamp": signal.timestamp,
            "dry_run": config.dry_run,
        }
        executed.append(order)

    result = {
        "orders": executed,
        "cash": round(cash, 2),
        "positions": {key: round(value, 8) for key, value in sorted(positions.items())},
        "trades_copied": len(executed),
        "dry_run": config.dry_run,
    }
    return result


def format_summary(result: Dict[str, Any]) -> str:
    lines = [
        f"Trades copied: {result['trades_copied']}",
        f"Remaining cash: ${result['cash']:.2f}",
        "Positions:",
    ]
    positions = result["positions"]
    if not positions:
        lines.append("  (none)")
    else:
        for symbol, quantity in positions.items():
            lines.append(f"  {symbol}: {quantity}")

    for order in result["orders"]:
        action = "PAPER" if order["dry_run"] else "LIVE"
        lines.append(
            f"- {action} {order['side'].upper()} {order['symbol']} qty={order['quantity']} "
            f"@ ${order['price']:.2f} from {order['leader']} (confidence {order['confidence']:.2f})"
        )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Copy-trade bot prototype with dry-run safety checks")
    parser.add_argument("--config", required=True, help="Path to bot config JSON")
    parser.add_argument("--signals", required=True, help="Path to a JSON list of trade signals")
    parser.add_argument("--json-output", action="store_true", help="Emit machine-readable JSON instead of a text summary")
    args = parser.parse_args()

    config = load_config(args.config)
    signals = load_signals(args.signals)
    result = run_copy_trading(signals, config)
    if args.json_output:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(format_summary(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
