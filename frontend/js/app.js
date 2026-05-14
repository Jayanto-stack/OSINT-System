const scanBtn = document.getElementById("scanBtn");

scanBtn.addEventListener("click", async () => {

    const name = document.getElementById("name").value;
    const email = document.getElementById("email").value;
    const phone = document.getElementById("phone").value;

    if(name === "" || email === ""){
        alert("Name and Email are required");
        return;
    }

    const userData = {
        name: name,
        email: email,
        phone: phone
    };

    try {

        const response = await fetch("http://127.0.0.1:8000/scan-risk", {

            method: "POST",

            headers: {
                "Content-Type": "application/json"
            },

            body: JSON.stringify(userData)

        });

        const data = await response.json();

        document.getElementById("result").innerHTML = `
            <p><strong>Name:</strong> ${data.name}</p>
            <p><strong>Email:</strong> ${data.email}</p>
            <p><strong>Risk Score:</strong> ${data.risk_score}</p>
            <p><strong>AI Summary:</strong> ${data.ai_summary}</p>
        `;

    } catch(error){

        console.error(error);

        alert("Backend connection failed");

    }

});
