import streamlit as st
from supabase import create_client, Client
import re
import os

# 🔧 Supabase credentials
SUPABASE_URL = st.secrets["SUPABASE_URL"]
SUPABASE_ANON_KEY = st.secrets["SUPABASE_ANON_KEY"]
supabase: Client = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)

st.set_page_config(page_title="Secure Login", page_icon="🔐")

# ---------------- SESSION STATE SETUP ----------------
if "user" not in st.session_state:
    st.session_state.user = None
if "session" not in st.session_state:
    st.session_state.session = None

# ---------------- HANDLE PASSWORD RESET REDIRECT ----------------
query_params = st.experimental_get_query_params()
access_token = query_params.get("access_token", [None])[0]
type_param = query_params.get("type", [None])[0]

if access_token and type_param == "recovery":
    try:
        session = supabase.auth.set_session(access_token, access_token)
        st.session_state.user = session.user
        st.session_state.session = session.session
        st.success("✅ Password reset successful. You're now logged in!")
    except Exception as e:
        st.error(f"❌ Failed to complete login after password reset: {e}")

# ---------------- PASSWORD VALIDATION ----------------
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

# ---------------- LOGGED IN VIEW ----------------
if st.session_state.user:
    st.title("✅ You are logged in")
    st.write(f"📧 Email: `{st.session_state.user['email']}`")

    if st.button("Logout"):
        st.session_state.user = None
        st.session_state.session = None
        st.rerun()

# ---------------- LOGIN / SIGN UP ----------------
else:
    st.title("🔐 Welcome to the App")

    mode = st.radio("Choose an option:", ["Login", "Sign Up"])
    email = st.text_input("Email")
    password = st.text_input("Password", type="password")

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

    elif mode == "Login":
        if st.button("Login"):
            res = supabase.auth.sign_in_with_password({"email": email, "password": password})
            if "error" in res.__dict__ and res.__dict__["error"]:
                st.error(f"❌ {res.__dict__['error'].message}")
            elif "session" in res.__dict__ and res.__dict__["session"]:
                st.success("✅ Logged in successfully!")
                st.session_state.user = res.__dict__["user"].model_dump()
                st.session_state.session = res.__dict__["session"]
                st.rerun()
            else:
                st.error("❌ Login failed. Unknown issue.")

    # ---------------- RESET PASSWORD ----------------
    with st.expander("🔁 Forgot your password?"):
        reset_email = st.text_input("Enter your email to reset password", key="reset_email_input")
        if st.button("Send Reset Link", key="send_reset_button"):
            try:
                res = supabase.auth.reset_password_for_email(
                    email=reset_email,
                    options={"redirect_to": "https://gamificationinstructorapp.streamlit.app"}
                )

                if hasattr(res, "error") and res.error:
                    st.error(f"❌ {res.error.message}")
                else:
                    st.success("✅ Check your email for the reset link.")
            except Exception as e:
                st.error(f"❌ Reset failed: {e}")
