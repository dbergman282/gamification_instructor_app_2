import streamlit as st
from supabase import create_client, Client
import re

# ------------------ INITIAL SETUP ------------------

st.set_page_config(page_title="Secure Login", page_icon="🔐")

# Supabase credentials from Streamlit secrets
SUPABASE_URL = st.secrets["SUPABASE_URL"]
SUPABASE_ANON_KEY = st.secrets["SUPABASE_ANON_KEY"]
supabase: Client = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)

# Session state setup
if "user" not in st.session_state:
    st.session_state.user = None
if "session" not in st.session_state:
    st.session_state.session = None

# ------------------ PASSWORD VALIDATION ------------------

def password_valid(password: str) -> bool:
    return (
        len(password) >= 8 and
        re.search(r"[A-Za-z]", password) and
        re.search(r"\d", password) and
        re.search(r"[!@#$%^&*(),.?\":{}|<>]", password)
    )

# ------------------ LOGGED IN VIEW ------------------

if st.session_state.user:
    st.title("✅ You are logged in")
    user = st.session_state.get("user")

    if user is None:
        st.error("⚠️ No user found in session. Please log in again.")
    elif isinstance(user, dict):
        st.write(f"📧 Email: `{user.get('email', 'N/A')}`")
        st.write(f"🆔 ID: `{user.get('id', 'N/A')}`")
    else:
        st.write(f"📧 Email: `{user.email}`")
        st.write(f"🆔 ID: `{user.id}`")

    # 🔒 Logout button
    if st.button("Logout"):
        st.session_state.user = None
        st.session_state.session = None
        st.session_state.page = None
        st.rerun()

    # ------------------ MAIN MENU ------------------

    if "page" not in st.session_state or st.session_state.page is None:
        st.subheader("What would you like to do?")
        col1, col2 = st.columns(2)

        with col1:
            if st.button("👀 View Classes"):
                st.session_state.page = "view_classes"
                st.rerun()

        with col2:
            if st.button("➕ Create New Class"):
                st.session_state.page = "create_class"
                st.rerun()

    # ------------------ SECTION CONTENT ------------------

    elif st.session_state.page == "view_classes":
        st.header("👀 View Classes")
        st.info("This is where you will add your logic to display classes.")
        if st.button("🔙 Back"):
            st.session_state.page = None
            st.rerun()

    elif st.session_state.page == "create_class":
        st.header("➕ Create New Class")
        st.info("This is where you will add your logic to create a new class.")
        if st.button("🔙 Back"):
            st.session_state.page = None
            st.rerun()

# ------------------ LOGIN / SIGN UP VIEW ------------------

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
                    supabase.auth.sign_in_with_password({
                        "email": email,
                        "password": password
                    })
                    st.error("❌ This email is already registered and confirmed. Please log in or reset your password.")
                except Exception as e:
                    if "Email not confirmed" in str(e):
                        st.warning("⚠️ This email is already registered but not confirmed. Check your inbox or reset your password.")
                    else:
                        try:
                            res = supabase.auth.sign_up({
                                "email": email,
                                "password": password
                            })
                            st.success("✅ Account created! Check your email to confirm before logging in.")
                        except Exception as signup_error:
                            st.error("❌ Error during sign-up.")
                            st.exception(signup_error)

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

    # ------------------ RESET PASSWORD ------------------

    with st.expander("🔁 Forgot your password?"):
        reset_email = st.text_input("Enter your email to reset password", key="reset_email_input")
        if st.button("Send Reset Link", key="send_reset_button"):
            try:
                res = supabase.auth.reset_password_for_email(
                    email=reset_email,
                    options = {
                      "redirect_to": "https://gamificationstate-reset-password.vercel.app"
                    }
                )
                st.success("✅ Check your email for the reset link.")
            except Exception as e:
                st.error("❌ Reset failed.")
                st.exception(e)
