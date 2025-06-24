import streamlit as st
from supabase import create_client, Client

# 🔧 Replace with your real Supabase credentials
SUPABASE_URL = "https://vbutahnefklmcmpygafx.supabase.co"
SUPABASE_ANON_KEY = "YOUR_SUPABASE_ANON_KEY"

supabase: Client = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)

st.set_page_config(page_title="Login", page_icon="🔐")
st.title("🔐 Login / Sign Up")

# Select between Login and Sign Up
mode = st.radio("Choose an option:", ["Login", "Sign Up"])

email = st.text_input("Email")
password = st.text_input("Password", type="password")

# Sign Up Flow
if mode == "Sign Up":
    if st.button("Create Account"):
        res = supabase.auth.sign_up({"email": email, "password": password})
        if res.get("error"):
            st.error(f"❌ {res['error']['message']}")
        else:
            st.success("✅ Account created! Check your email to confirm before logging in.")

# Login Flow
if mode == "Login":
    if st.button("Login"):
        try:
            res = supabase.auth.sign_in_with_password({"email": email, "password": password})
            if "session" in res and res["session"]:
                st.success("✅ Logged in successfully!")
                st.write("User info:", res["user"])
            else:
                st.error("❌ Login failed. Check your email confirmation or password.")
        except Exception as e:
            st.error("Login error.")
            st.code(str(e))

# Password Reset Flow
with st.expander("🔁 Forgot your password?"):
    reset_email = st.text_input("Enter your email for reset")
    if st.button("Send Reset Link"):
        res = supabase.auth.reset_password_for_email(
            email=reset_email,
            redirect_to="https://your-app.streamlit.app"  # replace with your hosted URL
        )
        if res.get("error"):
            st.error("❌ " + res["error"]["message"])
        else:
            st.success("✅ Check your email for the reset link.")
