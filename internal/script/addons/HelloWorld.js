exports.sayHello = (name) => {
  const text = "Hello, " + (name || "World") + "!";
  console.log(text);
  return text;
};
