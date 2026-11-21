const currentTime = document.getElementById('currentTime');

if (currentTime) {
	function showTime() {
		currentTime.textContent = new Date().toUTCString();
	}

	showTime();
	setInterval(showTime, 1000);
}
