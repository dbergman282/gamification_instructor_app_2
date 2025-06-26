import streamlit as st
from supabase import create_client, Client
import re

# 🔧 Supabase credentials from Streamlit secrets
SUPABASE_URL = st.secrets["SUPABASE_URL"]
SUPABASE_ANON_KEY = st.secrets["SUPABASE_ANON_KEY"]
supabase: Client = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)

st.set_page_config(page_title="Secure Login", page_icon="🔐")

# ---------------- SESSION STATE SETUP ----------------
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

# ---------------- HANDLE RESET PASSWORD FLOW ----------------
query_params = st.query_params or {}
access_token = query_params.get("access_token")
type_param = query_params.get("type")

if access_token and type_param == "recovery":
    st.title("🔒 Reset Your Password")
    new_pw = st.text_input("Enter new password", type="password")
    confirm_pw = st.text_input("Confirm new password", type="password")

    if st.button("Update Password"):
        if new_pw != confirm_pw:
            st.error("❌ Passwords do not match.")
        elif not password_valid(new_pw):
            st.error("❌ Password must have 8+ characters, a letter, a number, and a special character.")
        elif len(access_token.split(".")) != 3:
            st.error("❌ Invalid access token format.")
        else:
            try:
                session = supabase.auth.set_session(access_token, access_token)
                supabase.auth.update_user({"password": new_pw})
                st.session_state.user = session.user
                st.session_state.session = session.session
                st.success("✅ Password updated successfully. You are now logged in.")
                st.query_params.clear()
                st.rerun()
            except Exception as e:
                st.error(f"❌ Failed to reset password: {e}")
    st.stop()

# ---------------- LOGGED IN VIEW ----------------
if st.session_state.user:
    st.title("✅ You are logged in")
    
    user = st.session_state.get("user")

    if user is None:
        st.error("⚠️ No user found in session. Please log in again.")
    elif isinstance(user, dict):
        # If user is a dictionary
        st.write(f"📧 Email: `{user.get('email', 'N/A')}`")
        st.write(f"🆔 ID: `{user.get('id', 'N/A')}`")
        st.write(f"👤 Role: `{user.get('role', 'N/A')}`")
        st.write(f"🕒 Created at: `{user.get('created_at', 'N/A')}`")
    else:
        # If user is a Supabase user object
        st.write(f"📧 Email: `{user.email}`")
        st.write(f"🆔 ID: `{user.id}`")
        st.write(f"👤 Role: `{user.role}`")
        st.write(f"🕒 Created at: `{user.created_at}`")

    if st.button("Logout"):
        st.session_state.user = None
        st.session_state.session = None
        st.rerun()

# ---------------- LOGIN / SIGN UP VIEW ----------------
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
                try:
                    res = supabase.auth.sign_up({
                        "email": email,
                        "password": password
                    })

                    if hasattr(res, "user") and res.user:
                        st.success("✅ Account created! Check your email to confirm before logging in.")
                    else:
                        st.error("❌ Sign-up failed. Please try again.")
                except Exception as e:
                    st.error("❌ Error during sign-up.")
                    st.exception(e)

    elif mode == "Login":
        if st.button("Login"):
            try:
                res = supabase.auth.sign_in_with_password({"email": email, "password": password})
                if hasattr(res, "user") and res.user:
                    st.success("✅ Logged in successfully!")
                    st.session_state.user = res.user
                    st.session_state.session = res.session
                    st.rerun()
                else:
                    st.error("❌ Login failed. Check email and password.")
            except Exception as e:
                error_message = str(e)
                if "Email not confirmed" in error_message:
                    st.error("❌ Email not confirmed. Please check your inbox and confirm your email before logging in.")
                else:
                    st.error("❌ Login error. Please try again.")


    # ---------------- RESET PASSWORD ----------------
    with st.expander("🔁 Forgot your password?"):
        reset_email = st.text_input("Enter your email to reset password", key="reset_email_input")
        if st.button("Send Reset Link", key="send_reset_button"):
            try:
                res = supabase.auth.reset_password_for_email(
                    email=reset_email,
                    options={"redirect_to": "https://gamificationinstructorapp.streamlit.app"}
                )
                st.success("✅ Check your email for the reset link.")
            except Exception as e:
                st.error("❌ Reset failed.")
                st.exception(e)
