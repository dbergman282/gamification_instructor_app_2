import streamlit as st
from supabase import create_client, Client
import re

# 🔧 Replace with your real Supabase credentials
SUPABASE_URL = st.secrets["SUPABASE_URL"]
SUPABASE_ANON_KEY = st.secrets["SUPABASE_ANON_KEY"]

supabase: Client = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)

st.set_page_config(page_title="Secure Login", page_icon="🔐")
st.title("🔐 Welcome")

# Choose login or signup
mode = st.radio("Choose an option:", ["Login", "Sign Up"])

email = st.text_input("Email")
password = st.text_input("Password", type="password")

# ✅ Password rules
def password_valid(password: str) -> bool:
    if len(password) < 8:
        return False
    if not re.search(r"[A-Za-z]", password):
        return False
    if not re.search(r"\d", password):
        return False
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False
    return True

# ✅ Sign Up logic
if mode == "Sign Up":
    st.markdown("""
    🔐 **Password requirements:**
    - At least 8 characters  
    - Must include a **letter**, a **number**, and a **special character** (like `!`, `@`, `#`, etc.)
    """)
    if st.button("Create Account"):
        if not password_valid(password):
            st.error("❌ Password does not meet the requirements.")
        else:
            res = supabase.auth.sign_up({"email": email, "password": password})
            if res.get("error"):
                st.error(f"❌ {res['error']['message']}")
            else:
                st.success("✅ Account created! Check your email to confirm before logging in.")

# ✅ Login logic
elif mode == "Login":
    if st.button("Login"):
        try:
            res = supabase.auth.sign_in_with_password({"email": email, "password": password})
            if res.get("session"):
                st.success("✅ Logged in successfully!")
                st.write("User info:", res["user"])
            else:
                st.error("❌ Login failed. Check your credentials or confirm your email.")
        except Exception as e:
            st.error("Login error.")
            st.code(str(e))

# ✅ Password reset option
with st.expander("🔁 Forgot your password?"):
    reset_email = st.text_input("Enter your email to reset password")
    if st.button("Send Reset Link"):
        res = supabase.auth.reset_password_for_email(
            email=reset_email,
            redirect_to="https://your-app.streamlit.app"  # change this to your deployed URL
        )
        if res.get("error"):
            st.error("❌ " + res["error"]["message"])
        else:
            st.success("✅ Check your email for the reset link.")
