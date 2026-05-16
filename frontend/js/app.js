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
             `<p><strong>Name:</strong> ${data.name}</p>
             <p><strong>Email:</strong> ${data.email}</p>
             <p><strong>Risk Score:</strong> <span style="color:${data.risk_score === 'Critical' ? 'red' : data.risk_score === 'High' ? 'orange' : 'yellow'}">${data.risk_score}</span></p>
             <p><strong>Summary:</strong> ${data.ai_summary}</p>
             <p><strong>Digital Footprint:</strong> ${data.digital_footprint}</p>
             <p><strong>Breach Info:</strong> ${data.breach_summary}</p>
             <p><strong>Risk Reasons:</strong> ${data.risk_reasons?.join(", ")}</p>
             <p><strong>Recommendations:</strong> ${data.recommendations?.join(" | ")}</p>
             <p><strong>Public URLs Found:</strong> ${data.google_mentions?.length || 0}</p>
             <p><strong>Sites Registered On:</strong> ${data.registered_sites?.join(", ") || "None found"}</p>`;

    } catch(error){

        console.error("FULL ERROR:", error);

        alert("Backend connection failed");

    }

});
