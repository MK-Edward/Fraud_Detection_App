        return alert_redirect("Transfer amount must be greater than zero.")
    conn = get_db_connection()
    try:
        sender = conn.execute(
            "SELECT * FROM bank_accounts WHERE user_id = ?", (user["id"],)
        ).fetchone()
        receiver = conn.execute(
            "SELECT * FROM bank_accounts WHERE account_number = ?", (recipient_account.strip(),)
        ).fetchone()
        if not sender:
            return alert_redirect("No bank account found for this profile.")
        if not receiver:
            return alert_redirect("Recipient account does not exist.")
        if sender["id"] == receiver["id"]:
            return alert_redirect("You cannot transfer money to the same account.")
        try:
            current_lat = float(live_lat) if live_lat else float(sender["home_lat"])
            current_lon = float(live_lon) if live_lon else float(sender["home_lon"])
            if not (-90 <= current_lat <= 90 and -180 <= current_lon <= 180):
                raise ValueError
        except (ValueError, TypeError):
            current_lat, current_lon = float(sender["home_lat"]), float(sender["home_lon"])

        distance_home = calculate_gps_distance(
            sender["home_lat"], sender["home_lon"], current_lat, current_lon
        )
        pin_matched = verify_secret_string(input_pin, sender["pin_hash"])
        reason = "Approved"
        tx_status = "Completed"
        if not pin_matched:
            tx_status, reason = "Blocked", "PIN verification failed"
        elif distance_home > 1500.0:
            tx_status, reason = "Blocked", "Location is more than 1500 km from home county"

        if tx_status == "Blocked":
            conn.execute(
                """INSERT INTO transactions
                (sender_account, recipient_account, amount, distance_from_home, used_pin_number,
                 status, reason, tx_lat, tx_lon)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (sender["account_number"], recipient_account, amount, distance_home,
                 int(pin_matched), tx_status, reason, current_lat, current_lon),
            )
            conn.commit()
            return alert_redirect(f"Transfer blocked by demo risk checks: {reason}.")

        # Check and update both accounts in one transaction.
        if float(sender["balance"]) < amount:
            return alert_redirect("Insufficient checking balance.")
        conn.execute("UPDATE bank_accounts SET balance = balance - ? WHERE id = ?", (amount, sender["id"]))
        conn.execute("UPDATE bank_accounts SET balance = balance + ? WHERE id = ?", (amount, receiver["id"]))
        conn.execute(
            """INSERT INTO transactions
            (sender_account, recipient_account, amount, distance_from_home, used_pin_number,
             status, reason, tx_lat, tx_lon)
            VALUES (?, ?, ?, ?, 1, 'Completed', 'Approved', ?, ?)""",
            (sender["account_number"], receiver["account_number"], amount,
             distance_home, current_lat, current_lon),
        )
        conn.commit()
    except Exception:
        conn.rollback()
        logger.exception("Transaction processing failed")
        return alert_redirect("Transaction could not be processed. Check the application logs.")
    finally:
        conn.close()
    return alert_redirect("Transfer completed successfully.")


@app.get("/dashboard", response_class=HTMLResponse)
async def manager_dashboard_view(request: Request):
    user = get_request_user(request)
    if not user or user["role"] != "manager":
        return HTMLResponse(page("Access denied", '<div class="alert alert-danger">Manager access required.</div>'), status_code=403)
    conn = get_db_connection()
    try:
        total_tx = conn.execute("SELECT COUNT(*) AS total FROM transactions").fetchone()["total"]
        blocked_tx = conn.execute(
            "SELECT COUNT(*) AS total FROM transactions WHERE status = 'Blocked'"
        ).fetchone()["total"]
        ledger = conn.execute("SELECT * FROM transactions ORDER BY id DESC LIMIT 20").fetchall()
    finally:
        conn.close()
    rows = ""
    for tx in ledger:
        rows += (
            "<tr><td>" + html.escape(str(tx["timestamp"])[:19]) + "</td><td>" +
            html.escape(str(tx["sender_account"])) + " → " +
            html.escape(str(tx["recipient_account"])) + "</td><td>$" +
            f"{float(tx['amount']):.2f}</td><td>" + html.escape(str(tx["status"])) +
            "</td><td>" + html.escape(str(tx["reason"] or "")) + "</td></tr>"
        )
    body = f"""
<h2>🛡️ System control center</h2>
<div class="row g-3 my-3"><div class="col-md-6"><div class="card shadow-sm p-3">
<small>Total transactions</small><strong class="fs-3">{total_tx}</strong></div></div>
<div class="col-md-6"><div class="card shadow-sm p-3"><small>Blocked transactions</small>
<strong class="fs-3">{blocked_tx}</strong></div></div></div>
<div class="card shadow-sm p-4"><h4>📋 Transaction risk ledger</h4>
<div class="table-responsive"><table class="table table-striped">
<thead><tr><th>Timestamp</th><th>Accounts</th><th>Amount</th><th>Status</th><th>Reason</th></tr></thead>
<tbody>{rows or '<tr><td colspan="5">No transactions recorded.</td></tr>'}</tbody>
</table></div></div>"""
    return page("Manager dashboard", body)


@app.get("/health")
async def health():
    return {"status": "ok", "service": "unique-bank-demo"}
