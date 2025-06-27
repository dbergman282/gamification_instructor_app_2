import streamlit as st
import urllib.parse
import re
from supabase import create_client, Client

# ✅ Supabase credentials from secrets
SUPABASE_URL = st.secrets["SUPABASE_URL"]
SUPABASE_ANON_KEY = st.secrets["SUPABASE_ANON_KEY"]
supabase: Client = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)

# ✅ Password validation
def password_valid(password: str) -> bool:
    return (
        len(password) >= 8 and
        re.search(r"[A-Za-z]", password) and
        re.search(r"\d", password) and
        re.search(r"[!@#$%^&*(),.?\":{}|<>]", password)
    )

# ✅ Get token from URL fragment (after #)
def get_token_from_fragment() -> str:
    raw_url = st.experimental_get_url()
    parsed = urllib.parse.urlparse(raw_url)
    fragment_params = urllib.parse.parse_qs(parsed.fragment)
    return fragment_params.get("access_token", [None])[0]

# ✅ Main reset password logic
access_token = get_token_from_fragment()
if access_token:
    st.title("🔒 Reset Your Password")

    new_pw = st.text_input("Enter new password", type="password")
    confirm_pw = st.text_input("Confirm new password", type="password")

    if st.button("Update Password"):
        if new_pw != confirm_pw:
            st.error("❌ Passwords do not match.")
        elif not password_valid(new_pw):
            st.error("❌ Password must have 8+ characters, a letter, a number, and a special character.")
        else:
            try:
                # Set the session using the JWT token
                session = supabase.auth.set_session(access_token, access_token)
                supabase.auth.update_user({"password": new_pw})

                st.session_state.user = session.user
                st.session_state.session = session.session

                st.success("✅ Password updated successfully. You are now logged in.")
                st.rerun()
            except Exception as e:
                st.error(f"❌ Failed to reset password: {e}")
else:
    st.warning("⚠️ Invalid or missing reset token. Please use the link from your email.")
