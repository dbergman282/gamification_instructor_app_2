import streamlit as st
from supabase import create_client, Client
import re

# --- Supabase setup ---
SUPABASE_URL = st.secrets["SUPABASE_URL"]
SUPABASE_ANON_KEY = st.secrets["SUPABASE_ANON_KEY"]
supabase: Client = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)

# --- Password strength validator ---
def password_valid(password: str) -> bool:
    return (
        len(password) >= 8 and
        re.search(r"[A-Za-z]", password) and
        re.search(r"\d", password) and
        re.search(r"[!@#$%^&*(),.?\":{}|<>]", password)
    )

# --- Parse query parameters ---
query_params = st.query_params
access_token = query_params.get("access_token")
type_param = query_params.get("type")

if access_token and type_param and type_param[0] == "recovery":
    access_token = access_token[0]  # Convert from list to string
    st.title("🔒 Reset Your Password")

    new_pw = st.text_input("Enter new password", type="password")
    confirm_pw = st.text_input("Confirm new password", type="password")

    if st.button("Update Password"):
        if new_pw != confirm_pw:
            st.error("❌ Passwords do not match.")
        elif not password_valid(new_pw):
            st.error("❌ Password must have 8+ characters, a letter, a number, and a special character.")
        elif len(access_token.split(".")) != 3:
            st.error("❌ Invalid access token format. Please use the link sent to your email.")
        else:
            try:
                st.info("🔐 Updating password...")
                session = supabase.auth.set_session(access_token, access_token)
                supabase.auth.update_user({"password": new_pw})
                st.session_state.user = session.user
                st.session_state.session = session.session
                st.success("✅ Password updated successfully. You are now logged in.")
                st.query_params.clear()
                st.rerun()
            except Exception as e:
                st.error(f"❌ Failed to reset password: {e}")
else:
    st.warning("🔑 Invalid or expired password reset link.")
