window.onload = function () {
	var burger = document.querySelector(".nav-burger");
	var navigationElement = document.querySelector(".site-nav");
	var activeClass = "active";

	if (!burger || !navigationElement) return;

	burger.onclick = function () {
		var navigationClassList = navigationElement.classList;
		var hasProperty = navigationClassList.contains(activeClass);
		if (hasProperty) {
			navigationClassList.remove(activeClass);
		} else {
			navigationClassList.add(activeClass);
		}
	}
}