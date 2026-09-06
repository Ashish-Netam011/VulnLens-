// Structural fixture: arrow functions and const-assigned expressions.

const validate = (input) => input.length > 0;

const transform = (data) => {
  return data.map((x) => x * 2);
};

const fetchData = async (url) => {
  return fetch(url);
};

const chained = (x) => (y) => x + y;
