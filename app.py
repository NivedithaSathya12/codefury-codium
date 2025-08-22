import streamlit as st

# ---- PAGE CONFIG ----
st.set_page_config(page_title="Folk Arts Portal", page_icon="🎨", layout="centered")

# ---- TITLE PAGE ----
st.title("🎨 Folk Arts Portal")
st.subheader("Preserving India's Traditional Arts with AI & Gamification")

st.markdown(
    """
    Welcome to the **Folk Arts Portal** 🌿  
    A platform that blends **technology, culture, and creativity** to promote India's fading folk art traditions.

    🔹 **Discover & Learn**: Explore Warli, Madhubani, Pithora & more  
    🔹 **AI Chatbot**: Ask questions, get instant cultural insights  
    🔹 **Gamification**: Earn points, play quizzes & climb the leaderboard  
    🔹 **Artist Directory**: Support local artists by showcasing their work  
    🔹 **Dashboard**: Visualize participation & impact
    """
)

# ---- IMAGE BANNER ----
st.image(
    "https://i.ibb.co/bJy6SpH/folk-art-banner.jpg", 
    caption="Celebrating India's folk heritage", 
    use_container_width=True
)

# ---- CALL TO ACTION ----
if st.button("🚀 Enter the Portal"):
    st.switch_page("pages/1_Home.py")  # if you’re using multipage setup
    # OR you can just scroll to next section in single-file app
    
    


