import streamlit as st
from supabase import create_client, Client
import re

# 🔧 Replace with your real Supabase credentials
SUPABASE_URL = st.secrets["SUPABASE_URL"]
SUPABASE_ANON_KEY = st.secrets["SUPABASE_ANON_KEY"]



supabase: Client = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)

st.set_page_config(page_title="Secure Login", page_icon="🔐")
st.title("🔐 Welcome to the App")

# Mode selector
mode = st.radio("Choose an option:", ["Login", "Sign Up"])

# Input fields
email = st.text_input("Email")
password = st.text_input("Password", type="password")

# Password validation function
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

# ---------------- SIGN UP ----------------
if mode == "Sign Up":
    st.markdown("""
    🔐 **Password requirements:**
    - At least 8 characters  
    - Must include a **letter**, a **number**, and a **special character** (like `!`, `@`, `#`)
    """)
    
    if st.button("Create Account"):
        if not password_valid(password):
            st.error("❌ Password does not meet the requirements.")
        else:
            res = supabase.auth.sign_up({"email": email, "password": password})
            if "error" in res.__dict__ and res.__dict__["error"]:
                st.error(f"❌ {res.__dict__['error'].message}")
            else:
                st.success("✅ Account created! Check your email to confirm before logging in.")

# ---------------- LOGIN ----------------
elif mode == "Login":
    if st.button("Login"):
        res = supabase.auth.sign_in_with_password({"email": email, "password": password})
        if "error" in res.__dict__ and res.__dict__["error"]:
            st.error(f"❌ {res.__dict__['error'].message}")
        elif "session" in res.__dict__ and res.__dict__["session"]:
            st.success("✅ Logged in successfully!")
            st.write("🔍 User info:")
            st.json(res.__dict__["user"].model_dump())
        else:
            st.error("❌ Login failed. Unknown issue.")

# ---------------- RESET PASSWORD ----------------
with st.expander("🔁 Forgot your password?"):
    reset_email = st.text_input("Enter your email to reset password")
    if st.button("Send Reset Link"):
        res = supabase.auth.reset_password_for_email(
            email=reset_email,
            redirect_to="https://your-app.streamlit.app"  # Change to your actual Streamlit Cloud URL
        )
        if "error" in res.__dict__ and res.__dict__["error"]:
            st.error("❌ " + res.__dict__["error"].message)
        else:
            st.success("✅ Check your email for the reset link.")
