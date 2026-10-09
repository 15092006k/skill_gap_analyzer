
import streamlit as st
import pandas as pd
import plotly.express as px
import requests
import sqlite3
import hashlib
import hmac
import secrets
import html
import io
import re

from datetime import datetime
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle


# =========================================================
# CONFIGURATION
# =========================================================

st.set_page_config(
    page_title="Karishma Skill Gap Analyser",
    page_icon="🎓",
    layout="wide",
    initial_sidebar_state="expanded",
)

DB_PATH = Path(__file__).with_name("users.db")


# =========================================================
# DATABASE AND PASSWORD SECURITY
# =========================================================

def get_connection():
    return sqlite3.connect(DB_PATH)


def initialize_database():
    with get_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                salt BLOB NOT NULL,
                password_hash BLOB NOT NULL,
                created_at TEXT NOT NULL
            )
        """)


def hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_bytes(16)

    password_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        300000,
    )
    return salt, password_hash


def register_user(username, password):
    username = username.strip().lower()

    if not re.fullmatch(r"[a-z0-9_.-]{3,30}", username):
        return False, (
            "Username must be 3–30 characters and contain only "
            "letters, numbers, dots, underscores or hyphens."
        )

    if len(password) < 8:
        return False, "Password must contain at least 8 characters."

    salt, password_hash = hash_password(password)

    try:
        with get_connection() as conn:
            conn.execute(
                """
                INSERT INTO users
                (username, salt, password_hash, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (
                    username,
                    salt,
                    password_hash,
                    datetime.now().isoformat(timespec="seconds"),
                ),
            )
        return True, "Account created successfully. You can now log in."

    except sqlite3.IntegrityError:
        return False, "That username already exists. Please choose another."


def verify_user(username, password):
    username = username.strip().lower()

    with get_connection() as conn:
        result = conn.execute(
            """
            SELECT salt, password_hash
            FROM users
            WHERE username = ?
            """,
            (username,),
        ).fetchone()

    if result is None:
        return False

    salt, saved_hash = result
    _, entered_hash = hash_password(password, salt)

    return hmac.compare_digest(saved_hash, entered_hash)


initialize_database()


# =========================================================
# SESSION STATE
# =========================================================

defaults = {
    "authenticated": False,
    "username": "",
    "history": [],
    "assessment": None,
    "chat_history": [],
    "completed_tasks": [],
}

for key, value in defaults.items():
    if key not in st.session_state:
        st.session_state[key] = value


# =========================================================
# DESIGN
# =========================================================

st.markdown("""
<style>
.stApp {
    background: linear-gradient(135deg, #f5f3ff, #eef2ff, #fdf2f8);
}

[data-testid="stSidebar"] {
    background: linear-gradient(180deg, #312e81, #6d28d9, #9333ea);
}

[data-testid="stSidebar"] * {
    color: white !important;
}

.hero {
    padding: 30px;
    border-radius: 22px;
    color: white;
    text-align: center;
    background: linear-gradient(120deg, #4f46e5, #7c3aed, #c026d3);
    box-shadow: 0 10px 30px rgba(79,70,229,.2);
    margin-bottom: 24px;
    animation: fadeIn 0.8s ease-in-out;
}

.hero h1 {
    color: white;
    font-size: 36px;
}

.hero p {
    color: white;
    font-size: 16px;
}

.info-card {
    background: rgba(255,255,255,.92);
    border: 1px solid #ddd6fe;
    border-radius: 16px;
    padding: 20px;
    margin-bottom: 12px;
    box-shadow: 0 5px 18px rgba(79,70,229,.08);
}

.info-card h3 {
    color: #5b21b6;
}

div.stButton > button {
    border-radius: 10px;
    border: none;
    color: white;
    background: linear-gradient(90deg, #4f46e5, #9333ea);
    font-weight: 600;
    transition: .2s;
}

div.stButton > button:hover {
    color: white;
    transform: translateY(-2px);
}

@keyframes fadeIn {
    from {opacity: 0; transform: translateY(10px);}
    to {opacity: 1; transform: translateY(0);}
}
</style>
""", unsafe_allow_html=True)


# =========================================================
# LOGIN AND REGISTRATION PAGE
# =========================================================

def authentication_page():
    st.markdown("""
    <div class="hero">
        <h1>🎓 Karishma Skill Gap Analyser</h1>
        <p>Your personal career development and skill assessment platform</p>
    </div>
    """, unsafe_allow_html=True)

    left, center, right = st.columns([1, 1.25, 1])

    with center:
        st.markdown("## 🔐 Welcome!")

        mode = st.radio(
            "Choose an option",
            ["Login", "Create Account"],
            horizontal=True,
        )

        if mode == "Login":
            st.markdown("### Sign in to your account")

            with st.form("login_form"):
                username = st.text_input(
                    "Username",
                    placeholder="Enter your username",
                )
                password = st.text_input(
                    "Password",
                    type="password",
                    placeholder="Enter your password",
                )
                submitted = st.form_submit_button(
                    "Login",
                    use_container_width=True,
                )

            if submitted:
                if not username.strip() or not password:
                    st.error("Enter both username and password.")
                elif verify_user(username, password):
                    st.session_state.authenticated = True
                    st.session_state.username = username.strip().lower()
                    st.session_state.history = []
                    st.session_state.assessment = None
                    st.session_state.chat_history = []
                    st.session_state.completed_tasks = []
                    st.rerun()
                else:
                    st.error("Incorrect username or password.")

            st.caption(
                "New here? Select Create Account to register."
            )

        else:
            st.markdown("### Create your account")

            with st.form("register_form"):
                new_username = st.text_input(
                    "Choose a username",
                    placeholder="At least 3 characters",
                )
                new_password = st.text_input(
                    "Create a password",
                    type="password",
                    placeholder="At least 8 characters",
                )
                confirm_password = st.text_input(
                    "Confirm password",
                    type="password",
                )

                registered = st.form_submit_button(
                    "Create Account",
                    use_container_width=True,
                )

            if registered:
                if new_password != confirm_password:
                    st.error("The passwords do not match.")
                else:
                    ok, message = register_user(
                        new_username,
                        new_password,
                    )
                    if ok:
                        st.success(message)
                    else:
                        st.error(message)

        st.markdown("---")
        st.caption(
            "Your account is stored in a local database on this computer."
        )


# =========================================================
# CAREER SKILL REQUIREMENTS
# =========================================================

CAREERS = {
    "Data Scientist": {
        "Python": 5,
        "Statistics": 5,
        "Machine Learning": 5,
        "SQL": 4,
        "Data Visualization": 4,
        "Communication": 3,
    },
    "AI Engineer": {
        "Python": 5,
        "Machine Learning": 5,
        "Deep Learning": 5,
        "Mathematics": 4,
        "SQL": 3,
        "Communication": 3,
    },
    "Python Developer": {
        "Python": 5,
        "SQL": 4,
        "Problem Solving": 5,
        "Git": 4,
        "APIs": 4,
        "Communication": 3,
    },
    "Web Developer": {
        "HTML/CSS": 5,
        "JavaScript": 5,
        "Python": 3,
        "APIs": 4,
        "Git": 4,
        "Problem Solving": 4,
    },
    "Data Analyst": {
        "Python": 4,
        "SQL": 5,
        "Statistics": 4,
        "Excel": 5,
        "Data Visualization": 5,
        "Communication": 4,
    },
}


# =========================================================
# HELPER FUNCTIONS
# =========================================================

def calculate_assessment(career, ratings):
    requirements = CAREERS[career]
    rows = []

    for skill, required in requirements.items():
        current = ratings.get(skill, 1)
        gap = max(required - current, 0)

        if gap == 0:
            status = "Ready"
        elif gap <= 2:
            status = "Needs Improvement"
        else:
            status = "High Priority"

        rows.append({
            "Skill": skill,
            "Your Level": current,
            "Required Level": required,
            "Skill Gap": gap,
            "Status": status,
        })

    df = pd.DataFrame(rows)

    readiness = round(
        df["Your Level"].sum() / df["Required Level"].sum() * 100
    )

    return df, min(readiness, 100)


def create_pdf(student, career, df, readiness):
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4)
    styles = getSampleStyleSheet()

    styles.add(ParagraphStyle(
        name="PurpleTitle",
        parent=styles["Title"],
        textColor=colors.HexColor("#6D28D9"),
    ))

    story = [
        Paragraph(
            "Karishma Skill Gap Analyser",
            styles["PurpleTitle"],
        ),
        Paragraph("Skill Assessment Report", styles["Heading2"]),
        Spacer(1, 12),
        Paragraph(
            f"Student: {html.escape(str(student['name']))}",
            styles["Normal"],
        ),
        Paragraph(f"Username: {html.escape(str(student['username']))}",
                  styles["Normal"]),
        Paragraph(f"Age: {student['age']}", styles["Normal"]),
        Paragraph(
            f"Qualification: {html.escape(str(student['qualification']))}",
            styles["Normal"],
        ),
        Paragraph(
            f"Target Career: {html.escape(str(career))}",
            styles["Normal"],
        ),
        Paragraph(
            f"Date: {datetime.now().strftime('%d %b %Y')}",
            styles["Normal"],
        ),
        Spacer(1, 12),
        Paragraph(
            f"Career Readiness Score: {readiness}%",
            styles["Heading2"],
        ),
        Spacer(1, 12),
    ]

    table_data = [
        ["Skill", "Current", "Required", "Gap", "Status"]
    ]

    for _, row in df.iterrows():
        table_data.append([
            str(row["Skill"]),
            str(row["Your Level"]),
            str(row["Required Level"]),
            str(row["Skill Gap"]),
            str(row["Status"]),
        ])

    table = Table(
        table_data,
        repeatRows=1,
        colWidths=[140, 65, 65, 45, 120],
    )

    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#6D28D9")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.lightgrey),
        ("PADDING", (0, 0), (-1, -1), 7),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1),
         [colors.white, colors.HexColor("#F5F3FF")]),
    ]))

    story.append(table)
    story.append(Spacer(1, 15))
    story.append(Paragraph(
        "This score is an estimate based on self-reported skills. "
        "Improve high-gap skills with practice and projects. "
        "The score does not guarantee employment.",
        styles["Normal"],
    ))

    doc.build(story)
    buffer.seek(0)
    return buffer.getvalue()


def get_roadmap(df):
    priority = df.sort_values("Skill Gap", ascending=False)
    tasks = []

    for _, row in priority.iterrows():
        if row["Skill Gap"] > 0:
            tasks.append({
                "skill": row["Skill"],
                "gap": int(row["Skill Gap"]),
                "task": (
                    f"Study {row['Skill']} fundamentals, complete "
                    "practice exercises, and build a small project."
                ),
            })

    return tasks


# =========================================================
# MAIN APPLICATION
# =========================================================

if not st.session_state.authenticated:
    authentication_page()

else:
    st.sidebar.markdown("## 💜 Karishma Skill Gap Analyser")
    st.sidebar.write(f"Signed in as **{st.session_state.username}**")
    st.sidebar.markdown("---")

    page = st.sidebar.radio(
        "Navigation",
        [
            "🏠 Dashboard",
            "📊 Skill Assessment",
            "🗺️ Learning Roadmap",
            "🔎 Job Description Analyser",
            "🤖 AI Career Assistant",
            "📜 Assessment History",
        ],
    )

    if st.sidebar.button("🚪 Logout", use_container_width=True):
        st.session_state.authenticated = False
        st.session_state.username = ""
        st.session_state.assessment = None
        st.session_state.history = []
        st.session_state.chat_history = []
        st.session_state.completed_tasks = []
        st.rerun()

    st.markdown("""
    <div class="hero">
        <h1>🎓 Karishma Skill Gap Analyser</h1>
        <p>Discover your skills. Identify your gaps. Build your future.</p>
    </div>
    """, unsafe_allow_html=True)

    # -----------------------------------------------------
    # DASHBOARD
    # -----------------------------------------------------

    if page == "🏠 Dashboard":
        st.header("👋 Welcome to Your Dashboard")

        st.write(
            "Assess your skills, discover career gaps, and create a learning plan."
        )

        c1, c2, c3 = st.columns(3)

        with c1:
            st.markdown("""
            <div class="info-card">
                <h3>📊 Skill Assessment</h3>
                Rate your current skills and compare them with career requirements.
            </div>
            """, unsafe_allow_html=True)

        with c2:
            st.markdown("""
            <div class="info-card">
                <h3>🗺️ Learning Roadmap</h3>
                Build a step-by-step plan for improving your skills.
            </div>
            """, unsafe_allow_html=True)

        with c3:
            st.markdown("""
            <div class="info-card">
                <h3>🤖 AI Career Assistant</h3>
                Get learning advice from your local Ollama model.
            </div>
            """, unsafe_allow_html=True)

        if st.session_state.assessment:
            a = st.session_state.assessment

            st.subheader("Your Latest Assessment")
            m1, m2, m3 = st.columns(3)
            m1.metric("Target Career", a["career"])
            m2.metric("Readiness", f"{a['readiness']}%")
            m3.metric("Skills Assessed", len(a["df"]))
            st.progress(a["readiness"] / 100)
        else:
            st.info("Open Skill Assessment to get started.")

    # -----------------------------------------------------
    # SKILL ASSESSMENT
    # -----------------------------------------------------

    elif page == "📊 Skill Assessment":
        st.header("📊 Student Profile")

        with st.form("assessment_form"):
            c1, c2 = st.columns(2)

            with c1:
                student_name = st.text_input(
                    "Student Name",
                    placeholder="Enter your name",
                )
                age = st.number_input(
                    "Age", min_value=10, max_value=100, value=20
                )

            with c2:
                qualification = st.selectbox(
                    "Qualification",
                    [
                        "Intermediate", "Diploma", "B.Tech / B.E.",
                        "B.Sc.", "B.Com.", "B.A.", "M.Tech / M.E.",
                        "M.Sc.", "Other",
                    ],
                )
                career = st.selectbox(
                    "Target Career", list(CAREERS.keys())
                )

            st.subheader("Rate Your Skills")
            st.caption(
                "1 = Beginner | 2 = Basic | 3 = Intermediate | "
                "4 = Advanced | 5 = Expert"
            )

            ratings = {}

            for skill in CAREERS[career]:
                ratings[skill] = st.slider(
                    skill,
                    min_value=1,
                    max_value=5,
                    value=2,
                    key=f"rating_{career}_{skill}",
                )

            submitted = st.form_submit_button(
                "✨ Analyse My Skills",
                use_container_width=True,
            )

        if submitted:
            if not student_name.strip():
                st.error("Please enter your name.")
            else:
                df, readiness = calculate_assessment(career, ratings)

                student = {
                    "name": student_name.strip(),
                    "username": st.session_state.username,
                    "age": int(age),
                    "qualification": qualification,
                }

                assessment = {
                    "student": student,
                    "career": career,
                    "ratings": ratings.copy(),
                    "df": df,
                    "readiness": readiness,
                    "date": datetime.now().strftime("%d %b %Y, %I:%M %p"),
                }

                st.session_state.assessment = assessment
                st.session_state.history.append(assessment)
                st.success("Assessment completed successfully!")

        if st.session_state.assessment:
            a = st.session_state.assessment
            df = a["df"]

            st.subheader("🎯 Assessment Results")

            c1, c2, c3 = st.columns(3)
            c1.metric("Career Readiness", f"{a['readiness']}%")
            c2.metric("Skills Assessed", len(df))
            c3.metric(
                "Skills to Improve",
                int((df["Skill Gap"] > 0).sum()),
            )

            st.progress(a["readiness"] / 100)
            st.dataframe(df, use_container_width=True, hide_index=True)

            chart_df = df.melt(
                id_vars=["Skill"],
                value_vars=["Your Level", "Required Level"],
                var_name="Level Type",
                value_name="Level",
            )

            fig = px.bar(
                chart_df,
                x="Skill",
                y="Level",
                color="Level Type",
                barmode="group",
                range_y=[0, 5],
                title="Current Skills vs Required Skills",
                color_discrete_sequence=["#8B5CF6", "#06B6D4"],
            )
            st.plotly_chart(fig, use_container_width=True)

            radar = px.line_polar(
                df,
                r="Your Level",
                theta="Skill",
                line_close=True,
                range_r=[0, 5],
                title="Your Skill Radar Chart",
            )
            radar.update_traces(fill="toself")
            st.plotly_chart(radar, use_container_width=True)

            c1, c2 = st.columns(2)

            with c1:
                st.download_button(
                    "📥 Download CSV",
                    data=df.to_csv(index=False).encode("utf-8"),
                    file_name="skill_assessment.csv",
                    mime="text/csv",
                    use_container_width=True,
                )

            with c2:
                try:
                    pdf = create_pdf(
                        a["student"], a["career"], df, a["readiness"]
                    )
                    st.download_button(
                        "📄 Download PDF Report",
                        data=pdf,
                        file_name="skill_assessment.pdf",
                        mime="application/pdf",
                        use_container_width=True,
                    )
                except Exception as e:
                    st.error(f"PDF creation failed: {e}")

    # -----------------------------------------------------
    # LEARNING ROADMAP
    # -----------------------------------------------------

    elif page == "🗺️ Learning Roadmap":
        st.header("🗺️ Your Learning Roadmap")

        if not st.session_state.assessment:
            st.info("Complete a skill assessment first.")
        else:
            a = st.session_state.assessment
            roadmap = get_roadmap(a["df"])

            st.write(f"Target career: **{a['career']}**")

            if not roadmap:
                st.success(
                    "Your self-ratings meet all listed skill requirements. "
                    "Try building portfolio projects."
                )

            for index, item in enumerate(roadmap, start=1):
                task_id = f"{a['career']}_{item['skill']}"

                with st.container(border=True):
                    st.subheader(f"Week {index}: {item['skill']}")
                    st.write(item["task"])
                    st.caption(f"Skill gap: {item['gap']} level(s)")

                    done = st.checkbox(
                        "Mark as complete",
                        value=task_id in st.session_state.completed_tasks,
                        key=f"task_{task_id}",
                    )

                    if done and task_id not in st.session_state.completed_tasks:
                        st.session_state.completed_tasks.append(task_id)
                    elif not done and task_id in st.session_state.completed_tasks:
                        st.session_state.completed_tasks.remove(task_id)

            total = len(roadmap)
            completed = sum(
                1 for item in roadmap
                if f"{a['career']}_{item['skill']}"
                in st.session_state.completed_tasks
            )

            if total:
                st.subheader("🏆 Progress")
                st.progress(completed / total)
                st.write(f"{completed} of {total} tasks completed.")

    # -----------------------------------------------------
    # JOB DESCRIPTION ANALYSER
    # -----------------------------------------------------

    elif page == "🔎 Job Description Analyser":
        st.header("🔎 Job Description Analyser")

        description = st.text_area(
            "Paste a job or internship description",
            height=220,
            placeholder="Paste the job description here...",
        )

        if st.button("Analyse Job Description"):
            if not description.strip():
                st.warning("Please paste a description.")
            else:
                known_skills = sorted(
                    {
                        skill
                        for skill_map in CAREERS.values()
                        for skill in skill_map
                    },
                    key=len,
                    reverse=True,
                )

                found = []

                for skill in known_skills:
                    pattern = (
                        r"(?<!\w)" + re.escape(skill.lower()) + r"(?!\w)"
                    )
                    if re.search(pattern, description.lower()):
                        found.append(skill)

                st.subheader("📌 Skills Detected")

                if found:
                    st.write(", ".join(found))
                else:
                    st.info("No recognised skills from the built-in list were found.")

                if st.session_state.assessment and found:
                    df = st.session_state.assessment["df"]

                    current = {
                        row["Skill"]: row["Your Level"]
                        for _, row in df.iterrows()
                    }

                    matched = [s for s in found if s in current]
                    missing = [s for s in found if s not in current]

                    c1, c2 = st.columns(2)

                    with c1:
                        st.subheader("Skills in Your Assessment")
                        for skill in matched:
                            st.write(f"• {skill}: Level {current[skill]}/5")
                        if not matched:
                            st.write("No matching skills.")

                    with c2:
                        st.subheader("Other Detected Skills")
                        for skill in missing:
                            st.write(f"• {skill}")
                        if not missing:
                            st.write("No additional detected skills.")

                st.caption(
                    "This feature matches keywords only. It cannot determine "
                    "whether a job is genuine or guarantee your suitability."
                )

    # -----------------------------------------------------
    # LOCAL OLLAMA AI ASSISTANT
    # -----------------------------------------------------

    elif page == "🤖 AI Career Assistant":
        st.header("🤖 AI Career Assistant")

        st.write(
            "Ask about Python, interviews, projects, career paths, or learning plans."
        )

        st.info(
            "This feature requires Ollama and the llama3.2 model on your Mac."
        )

        for message in st.session_state.chat_history:
            with st.chat_message(message["role"]):
                st.markdown(message["content"])

        prompt = st.chat_input("Ask your question...")

        if prompt:
            st.session_state.chat_history.append({
                "role": "user",
                "content": prompt,
            })

            with st.chat_message("user"):
                st.markdown(prompt)

            with st.chat_message("assistant"):
                with st.spinner("AI is thinking..."):
                    try:
                        context = ""

                        if st.session_state.assessment:
                            a = st.session_state.assessment
                            context = (
                                f"Target career: {a['career']}. "
                                f"Readiness: {a['readiness']}%. "
                                f"Skill data: {a['df'].to_dict(orient='records')}. "
                            )

                        response = requests.post(
                            "http://localhost:11434/api/generate",
                            json={
                                "model": "llama3.2",
                                "prompt": (
                                    "You are a helpful beginner-friendly career "
                                    "and programming tutor. Give clear, practical "
                                    "answers. Do not guarantee employment. "
                                    + context
                                    + "\nQuestion: "
                                    + prompt
                                ),
                                "stream": False,
                            },
                            timeout=180,
                        )

                        response.raise_for_status()
                        answer = response.json().get(
                            "response",
                            "The model returned no answer.",
                        )

                    except requests.exceptions.ConnectionError:
                        answer = (
                            "Cannot connect to Ollama. Run `ollama list` in "
                            "Terminal. If needed, run `ollama serve` in another "
                            "Terminal window and install the model with "
                            "`ollama pull llama3.2`."
                        )

                    except requests.exceptions.Timeout:
                        answer = (
                            "The AI response timed out. Try a shorter question."
                        )

                    except Exception as e:
                        answer = f"AI request failed: {e}"

                    st.markdown(answer)

            st.session_state.chat_history.append({
                "role": "assistant",
                "content": answer,
            })

        if st.button("Clear Chat History"):
            st.session_state.chat_history = []
            st.rerun()

    # -----------------------------------------------------
    # ASSESSMENT HISTORY
    # -----------------------------------------------------

    elif page == "📜 Assessment History":
        st.header("📜 Assessment History")

        st.caption(
            "This history is stored in the current app session and is cleared "
            "when you log out or the session resets."
        )

        if not st.session_state.history:
            st.info("No assessments recorded in this session.")
        else:
            rows = []

            for item in st.session_state.history:
                rows.append({
                    "Date": item["date"],
                    "Student": item["student"]["name"],
                    "Career": item["career"],
                    "Readiness (%)": item["readiness"],
                    "Skills Assessed": len(item["df"]),
                })

            history_df = pd.DataFrame(rows)

            st.dataframe(
                history_df,
                use_container_width=True,
                hide_index=True,
            )

            st.download_button(
                "Download History CSV",
                data=history_df.to_csv(index=False).encode("utf-8"),
                file_name="assessment_history.csv",
                mime="text/csv",
            )

            if st.button("Clear Assessment History"):
                st.session_state.history = []
                st.session_state.assessment = None
                st.success("History cleared.")
                st.rerun()

    # -----------------------------------------------------
    # FOOTER
    # -----------------------------------------------------

    st.markdown("---")
    st.markdown(
        """
        <div style="text-align:center; color:#6b7280; padding:10px;">
            <b>Karishma Skill Gap Analyser</b><br>
            Learn • Assess • Improve • Grow 🚀
        </div>
        """,
        unsafe_allow_html=True,
    )