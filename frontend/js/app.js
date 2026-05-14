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

    console.log(userData);

    // Temporary fake result
    document.getElementById("result").innerHTML = `
        <p><strong>Name:</strong> ${name}</p>
        <p><strong>Email:</strong> ${email}</p>
        <p><strong>Risk Score:</strong> Medium</p>
        <p><strong>AI Summary:</strong> Public email exposure detected.</p>
    `;

});
