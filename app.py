import streamlit as st,sqlite3
from pathlib import Path
st.set_page_config(page_title="Tor Watch Public OSINT",layout="wide")
st.title("Tor Watch — Public OSINT"); st.caption("Registered public .onion pages only")
db=Path("data/history.db")
if not db.exists(): st.info("No data yet. Run: python -m torwatch.cli --demo"); st.stop()
con=sqlite3.connect(db); rows=con.execute("SELECT url,title,risk,reasons,checked_at FROM pages ORDER BY risk DESC,checked_at DESC").fetchall(); con.close()
c1,c2,c3=st.columns(3); c1.metric("Monitored pages",len(rows)); c2.metric("High risk (>=40)",sum(r[2]>=40 for r in rows)); c3.metric("Critical (>=70)",sum(r[2]>=70 for r in rows))
st.subheader("Risk")
for url,title,risk,reasons,checked in rows:
    with st.expander(f"[{risk}] {title or url}"):
        st.write(url); st.write("Checked:",checked); st.write("Reasons:",reasons or "—")
        if risk>=70: st.error("CRITICAL")
        elif risk>=40: st.warning("HIGH")
        else: st.success("LOW / INFO")
