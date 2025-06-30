import streamlit as st
from supabase import create_client, Client
import re
import random
import string
from datetime import datetime, timezone, timedelta
from PIL import Image
import base64
from io import BytesIO

# ------------------ INITIAL SETUP ------------------


# Load the image (adjust path if needed)
logo = Image.open("gamification_state_logo.png")


st.set_page_config(
    page_title="Gamification State",
    page_icon=logo,
    layout="centered"
)

SUPABASE_URL = st.secrets["SUPABASE_URL"]
SUPABASE_ANON_KEY = st.secrets["SUPABASE_ANON_KEY"]
supabase: Client = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)

def set_supabase_auth(token: str, refresh_token: str):
    """Attach the JWT so Supabase knows the user is authenticated."""
    supabase.auth.set_session(token, refresh_token)
    supabase.postgrest.auth(token)   # ✅ Add this line!
    # st.write("✅ postgrest.auth(token) CALLED")

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

from datetime import datetime, timezone, timedelta

def show_view_classes():
    st.header("👀 Your Classes")

    # ✅ Get user_id from session
    user_id = (
        st.session_state.user.get("id")
        if isinstance(st.session_state.user, dict)
        else getattr(st.session_state.user, "id", None)
    )

    if not user_id:
        st.error("❌ No user ID found. Please log in again.")
        return

    # ✅ Attach JWT for SELECT
    if st.session_state.session:
        set_supabase_auth(
            st.session_state.session.access_token,
            st.session_state.session.refresh_token
        )
        st.write("✅ postgrest.auth(token) CALLED for SELECT")

    # ✅ Fetch this user's classes
    try:
        resp = supabase.table("classes").select("*").eq("user_id", user_id).order("created_at", desc=True).execute()
        classes = resp.data

        if not classes:
            st.info("ℹ️ You have no classes yet. Create one!")
        else:
            for cls in classes:
                created_at_utc = datetime.fromisoformat(cls["created_at"].replace("Z", "+00:00"))
                est_offset = timedelta(hours=-5)  # Or use pytz for daylight saving, but this is simple
                created_at_est = (created_at_utc + est_offset).strftime("%Y-%m-%d %I:%M %p EST")

                with st.expander(f"📚 {cls['class_name']} — Code: `{cls['class_code']}`"):
                    st.write(f"🗓️ Created at: {created_at_est}")
                    if st.button(f"🔍 View Details — `{cls['class_code']}`"):
                        st.info("🚧 Coming soon: Student info for this class!")

    except Exception as e:
        st.error("❌ Failed to load classes.")
        st.exception(e)

    if st.button("🔙 Back"):
        st.session_state.page = None
        st.rerun()


# ------------------ CLASS CODE GENERATOR ------------------

def generate_class_code(existing_codes=None, length=8):
    """
    Generates a unique alphanumeric class code.
    Excludes ambiguous characters (like 'O').
    """
    chars = [c for c in string.ascii_uppercase if c != "O"] + [str(d) for d in range(1, 10)]
    tries = 0
    while True:
        code = ''.join(random.choices(chars, k=length))
        if existing_codes is None or code not in existing_codes:
            return code
        tries += 1
        if tries > 100:
            raise ValueError("⚠️ Too many attempts to generate a unique class code.")

def show_create_class():
    st.header("➕ Create New Class")
    st.info("Course names must be unique and should not duplicate a class you already created.")

    course_name = st.text_input("📚 Course Name")

    if st.button("Create"):
        if not course_name.strip():
            st.error("❌ Course name cannot be empty.")
            return

        # ✅ Get user info
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

        # ✅ Attach JWT and test SELECT
        if st.session_state.session:
            set_supabase_auth(
                st.session_state.session.access_token,
                st.session_state.session.refresh_token
            )
            # st.write("✅ postgrest.auth(token) CALLED")
            # st.write("Session User ID:", user_id)

            # 🧪 Run a test SELECT
            test_resp = supabase.table("classes").select("*").eq("user_id", user_id).execute()
            # st.write("🔍 Test SELECT Response:", test_resp.data)

        # ✅ Check for duplicate class name
        dup_resp = supabase.table("classes").select("id").eq("user_id", user_id).eq("class_name", course_name).execute()
        if dup_resp.data and len(dup_resp.data) > 0:
            st.error("❌ You already have a class with that name.")
            return

        # ✅ Get existing codes
        codes_resp = supabase.table("classes").select("class_code").execute()
        existing_codes = [row["class_code"] for row in codes_resp.data]

        # ✅ Generate unique code
        generated_code = generate_class_code(existing_codes)
        # st.write("DEBUG:", {
        #     "user_email": user_email,
        #     "user_id": user_id,
        #     "course_name": course_name,
        #     "class_code": generated_code
        # })

        # ✅ Final insert
        try:
            # st.success("✅ Insert will run with JWT attached")

            insert_resp = supabase.table("classes").insert({
                "user_email": user_email,
                "class_name": course_name,
                "class_code": generated_code,
                "user_id": user_id
            }).execute()

            # st.write("Insert Response:", insert_resp)

            if insert_resp.data and len(insert_resp.data) > 0:
                st.success("✅ Class created successfully!")
                st.write(f"🆔 **Your unique class code is:** `{generated_code}`")
            else:
                st.error("❌ Insert returned no data. Please try again.")

        except Exception as e:
            # ✅ Friendly error message for unique violation
            if "23505" in str(e):
                st.error("❌ That class code already exists. Try again.")
            else:
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
        # st.write("Access Token:", st.session_state.session.access_token)

    if user is None:
        st.error("⚠️ No user found in session. Please log in again.")
    elif isinstance(user, dict):
        st.write(f"📧 Email: `{user.get('email', 'N/A')}`")
        # st.write(f"🆔 ID: `{user.get('id', 'N/A')}`")
    else:
        st.write(f"📧 Email: `{user.email}`")
        # st.write(f"🆔 ID: `{user.id}`")

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
        show_view_classes()

    elif st.session_state.page == "create_class":
        show_create_class()

# ------------------ LOGIN / SIGN UP VIEW ------------------

else:
    # Convert to base64
    buffer = BytesIO()
    logo.save(buffer, format="PNG")
    img_str = base64.b64encode(buffer.getvalue()).decode()
    
    # Display with flexbox and proper HTML
    st.markdown(
        f"""
        <div style='display: flex; align-items: center;'>
            <img src="data:image/png;base64,{img_str}" width="60" style='margin-right: 15px;'/>
            <h2 style='margin: 0;'>Gamification State Instructor Dashboard</h2>
        </div>
        """,
        unsafe_allow_html=True
    )

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

                    # st.write("Access Token:", res.session.access_token)
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
