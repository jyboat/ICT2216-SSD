# 📚 StudyNest

**StudyNest** is a Learning Management System (LMS) that provides essential course management features while implementing secure coding practices throughout. StudyNest allows students, educators, and administrators to interact in a central, structured environment. Core functionality includes user authentication, course enrollment, announcement publishing, material uploads, and a discussion forum. All user flows are designed with a focus on security, privacy, and safe data handling.

---

## 🔐 Key Features

- **Secure Login & Registration** with session protection  
- **Two-Factor Authentication (2FA)** support  
- **CSRF protection** for all sensitive operations  
- **Session hijacking detection** using fingerprinting  
- **Role-based access** (Admin, Educator, Student)  
- **Course & material management**  
- **Announcements and forums**  
- **Error handling with logging**

---

## 🗂️ Project Structure

ICT2216-SSD/
│
├── app.py # Main Flask application
├── templates/ # HTML templates (login, error, etc.)
├── static/ # Static files (CSS)
├── modules/ # Modular route logic (auth, forum, etc.)
├── test_app.py # Basic tests
├── requirements.txt # Project dependencies
├── Dockerfile # Docker build configuration
└── docker-compose.yml # Service orchestration

---

## 🏁 How It Works

- Users log in through a secure portal and are redirected based on role  
- Sessions are monitored for expiration and fingerprint mismatches  
- Educators can manage courses, upload materials, and post announcements  
- Students can access their enrolled courses, view updates, and participate in discussions  
- Admins manage users through a dedicated interface  

---

## 📫 Contact

**StudyNest Team Members:**

- **CALEB LEE JIA JING** – 2301831@sit.singaporetech.edu.sg
- **CHAI JUN YU** – 2301847@sit.singaporetech.edu.sg
- **CHIA QI JUN** – 2301848@sit.singaporetech.edu.sg
- **GOH MING QUAN** – 2301877@sit.singaporetech.edu.sg
- **LIM MIANG HOW MATTHEW** – 2301820@sit.singaporetech.edu.sg
- **SAITO YUGO** – 2301793@sit.singaporetech.edu.sg 
- **SHAWN KUIK** – 2301897@sit.singaporetech.edu.sg  
- **TAY HAO XIANG RYAN** – 2301851@sit.singaporetech.edu.sg