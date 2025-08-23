// script.js
auth.onAuthStateChanged(user => {
  if (user) {
    window.location.href = "dashboard.html";
  }
});

// Signup
function signup() {
  const email = document.getElementById("email").value;
  const password = document.getElementById("password").value;
  auth.createUserWithEmailAndPassword(email, password)
    .catch(error => alert(error.message));
}

// Login
function login() {
  const email = document.getElementById("email").value;
  const password = document.getElementById("password").value;
  auth.signInWithEmailAndPassword(email, password)
    .catch(error => alert(error.message));
}

// Upload Artwork
function uploadArtwork() {
  const title = document.getElementById("title").value;
  const description = document.getElementById("description").value;
  const file = document.getElementById("image").files[0];
  const reader = new FileReader();

  reader.onload = function () {
    db.collection("artworks").add({
      userId: auth.currentUser.uid,
      title,
      description,
      image: reader.result
    }).then(() => {
      loadGallery();
    });
  };
  reader.readAsDataURL(file);
}

// Load Gallery
function loadGallery() {
  const gallery = document.getElementById("gallery");
  gallery.innerHTML = "";

  db.collection("artworks")
    .where("userId", "==", auth.currentUser.uid)
    .get()
    .then(snapshot => {
      const uploads = snapshot.docs;
      uploads.forEach(doc => {
        const data = doc.data();
        const card = document.createElement("div");
        card.className = "card";
        card.innerHTML = `
          <img src="${data.image}" alt="${data.title}" />
          <h3>${data.title}</h3>
          <p>${data.description}</p>
        `;
        gallery.appendChild(card);
      });

      if (uploads.length >= 3) {
        document.getElementById("badge").style.display = "inline";
      }
    });
}