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

    console.log("Sending Data:", userData);

    try {

        const response = await fetch("/scan-risk", {

            method: "POST",

            headers: {
                "Content-Type": "application/json"
            },

            body: JSON.stringify(userData)

        });

        console.log("Respose Object:", response);

        const data = await response.json();
        console.log("JSON Data:", data);
        console.log("RESULT DIV:", document.getElementById("result"));

        document.getElementById("result").innerHTML =
            "<p><strong>Name:</strong> " + data.name + "</p>" +
            "<p><strong>Email:</strong> " + data.email + "</p>" +
            "<p><strong>Risk Score:</strong> " + data.risk_score + "</p>" +
            "<p><strong>AI Summary:</strong> " + data.ai_summary + "</p>"
            ;

    } catch(error){

        console.error("FULL ERROR:", error);

        alert("Backend connection failed");

    }

});
