import streamlit as st
from supabase import create_client, Client
import re
import random
import string

# ------------------ INITIAL SETUP ------------------

st.set_page_config(page_title="Secure Login", page_icon="🔐")

SUPABASE_URL = st.secrets["SUPABASE_URL"]
SUPABASE_ANON_KEY = st.secrets["SUPABASE_ANON_KEY"]
supabase: Client = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)

def set_supabase_auth(token: str, refresh_token: str):
    """Attach the JWT so Supabase knows the user is authenticated."""
    supabase.auth.set_session(token, refresh_token)

# ------------------ SESSION STATE ------------------

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

# ------------------ CLASS CODE GENERATOR ------------------

def generate_class_code(existing_codes=None):
    chars = [c for c in string.ascii_uppercase if c != "O"] + [str(d) for d in range(1, 10)]
    while True:
        code = ''.join(random.choices(chars, k=8))
        if existing_codes is None or code not in existing_codes:
            return code
# ------------------ CREATETABLE ------------------
def show_create_class():
    st.header("➕ Create New Class")
    st.info("Course names should be unique and should not duplicate a class you already created.")

    course_name = st.text_input("📚 Course Name")

    if st.button("Create"):
        if not course_name.strip():
            st.error("❌ Course name cannot be empty.")
            return

        # ✅ Get user email & user_id from session
        user_email = (
            st.session_state.user.get("email")
            if isinstance(st.session_state.user, dict)
            else getattr(st.session_state.user, "email", None)
        )
        user_id = (
            st.session_state.user.get("id")
            if isinstance(st.session_state.user, dict)
            else getattr(st.session_state.user, "id", None)
        )

        if not user_email or not user_id:
            st.error("❌ No user info found — please log in again.")
            return

        # ✅ Attach JWT before insert
        if st.session_state.session:
            set_supabase_auth(
                st.session_state.session.access_token,
                st.session_state.session.refresh_token
            )
            st.write("Session User ID:", user_id)
            st.write("Access Token:", st.session_state.session.access_token)

        # ✅ Check for duplicate
        response = supabase.table("classes").select("id").eq("user_id", user_id).eq("class_name", course_name).execute()
        if response.data and len(response.data) > 0:
            st.error("❌ You already have a class with that name.")
            return

        # ✅ Generate unique code
        existing_codes_resp = supabase.table("classes").select("class_code").execute()
        existing_codes = [row["class_code"] for row in existing_codes_resp.data]
        generated_code = generate_class_code(existing_codes)

        st.write("DEBUG:", {
            "user_email": user_email,
            "user_id": user_id,
            "course_name": course_name,
            "class_code": generated_code
        })

        # ✅ Final secure insert
        try:
            insert_resp = supabase.table("classes").insert({
                "user_email": user_email,
                "class_name": course_name,
                "class_code": generated_code,
                "user_id": user_id   # ✅ Pass real UUID!
            }).execute()

            st.write("Insert Response:", insert_resp)

            if insert_resp.error:
                st.error("❌ Failed to create class.")
                st.error(insert_resp.error)
            else:
                st.success("✅ Class created successfully!")
                st.write(f"🆔 **Your unique class code is:** `{generated_code}`")

        except Exception as e:
            st.error("❌ Exception thrown during insert:")
            st.exception(e)

    if st.button("🔙 Back"):
        st.session_state.page = None
        st.rerun()


# ------------------ LOGGED IN VIEW ------------------

if st.session_state.user:
    st.title("✅ You are logged in")
    user = st.session_state.get("user")

    # ✅ Ensure your Supabase client is always using the JWT
    if st.session_state.session:
        set_supabase_auth(
            st.session_state.session.access_token,
            st.session_state.session.refresh_token
        )
        st.write("Access Token:", st.session_state.session.access_token)

    if user is None:
        st.error("⚠️ No user found in session. Please log in again.")
    elif isinstance(user, dict):
        st.write(f"📧 Email: `{user.get('email', 'N/A')}`")
        st.write(f"🆔 ID: `{user.get('id', 'N/A')}`")
    else:
        st.write(f"📧 Email: `{user.email}`")
        st.write(f"🆔 ID: `{user.id}`")

    if st.button("Logout"):
        st.session_state.user = None
        st.session_state.session = None
        st.session_state.page = None
        st.rerun()

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

    elif st.session_state.page == "view_classes":
        st.header("👀 View Classes")
        st.info("This is where you will add your logic to display classes.")
        if st.button("🔙 Back"):
            st.session_state.page = None
            st.rerun()

    elif st.session_state.page == "create_class":
        show_create_class()

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

                    # ✅ Attach the JWT for all requests
                    set_supabase_auth(res.session.access_token, res.session.refresh_token)

                    st.write("Access Token:", res.session.access_token)
                    st.rerun()
                else:
                    st.error("❌ Login failed. Check email and password.")
            except Exception as e:
                error_message = str(e)
                if "Email not confirmed" in error_message:
                    st.error("❌ Email not confirmed. Please check your inbox and confirm your email before logging in.")
                else:
                    st.error("❌ Login error. Please try again.")

    with st.expander("🔁 Forgot your password?"):
        reset_email = st.text_input("Enter your email to reset password", key="reset_email_input")
        if st.button("Send Reset Link", key="send_reset_button"):
            try:
                res = supabase.auth.reset_password_for_email(
                    email=reset_email,
                    options={
                        "redirect_to": "https://gamificationstate-reset-password.vercel.app"
                    }
                )
                st.success("✅ Check your email for the reset link.")
            except Exception as e:
                st.error("❌ Reset failed.")
                st.exception(e)
