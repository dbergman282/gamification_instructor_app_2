import streamlit as st
from supabase import create_client, Client
import re

# 🔧 Supabase credentials
SUPABASE_URL = st.secrets["SUPABASE_URL"]
SUPABASE_ANON_KEY = st.secrets["SUPABASE_ANON_KEY"]
supabase: Client = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)

st.set_page_config(page_title="Secure Login", page_icon="🔐")

# ---------------- SESSION STATE ----------------
if "user" not in st.session_state:
    st.session_state.user = None
if "session" not in st.session_state:
    st.session_state.session = None

# ---------------- PASSWORD VALIDATION ----------------
def password_valid(password: str) -> bool:
    return (
        len(password) >= 8 and
        re.search(r"[A-Za-z]", password) and
        re.search(r"\d", password) and
        re.search(r"[!@#$%^&*(),.?\":{}|<>]", password)
    )

# ---------------- HANDLE RESET PASSWORD ----------------
params = st.query_params
access_token = params.get("access_token", None)
type_param = params.get("type", None)

if access_token and type_param == "recovery":
    st.title("🔒 Reset Your Password")

    if "." not in access_token:
        st.error("❌ Invalid or expired token. Please request a new password reset email.")
        st.stop()

    new_pw = st.text_input("Enter new password", type="password")
    confirm_pw = st.text_input("Confirm new password", type="password")

    if st.button("Update Password"):
        if new_pw != confirm_pw:
            st.error("❌ Passwords do not match.")
        elif not password_valid(new_pw):
            st.error("❌ Password must have 8+ characters, a letter, a number, and a special character.")
        else:
            try:
                session_response = supabase.auth.set_session(access_token, access_token)
                update_response = supabase.auth.update_user({"password": new_pw})

                if update_response and update_response.user:
                    st.success("✅ Password updated successfully. You are now logged in.")
                    st.session_state.user = update_response.user
                    st.session_state.session = session_response.session
                    st.query_params.clear()
                    st.rerun()
                else:
                    st.error("❌ Password update failed.")
            except Exception as e:
                st.exception(e)
    st.stop()


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
        - Must include a **letter**, a **number**, and a **special character**
        """)
        if st.button("Create Account"):
            if not password_valid(password):
                st.error("❌ Password does not meet the requirements.")
            else:
                res = supabase.auth.sign_up({"email": email, "password": password})
                if res.error:
                    st.error(f"❌ {res.error.message}")
                else:
                    st.success("✅ Account created! Check your email to confirm.")

    elif mode == "Login":
        if st.button("Login"):
            res = supabase.auth.sign_in_with_password({"email": email, "password": password})
            if res.error:
                st.error(f"❌ {res.error.message}")
            elif res.session:
                st.success("✅ Logged in successfully!")
                st.session_state.user = res.user.model_dump()
                st.session_state.session = res.session
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
                if res.error:
                    st.error(f"❌ {res.error.message}")
                else:
                    st.success("✅ Check your email for the reset link.")
            except Exception as e:
                st.error(f"❌ Reset failed: {e}")
