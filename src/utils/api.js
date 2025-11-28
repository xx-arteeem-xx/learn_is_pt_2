export async function api(method, endpoint, data = null, dataType = "JSON") {
    // || __________________  ЗАДАЕМ ЗАГОЛОВКИ ЗАПРОСА  _______________________ || 
    let headers = new Headers();
    if (dataType === "JSON") {
        headers.append('Content-Type', 'application/json'); 
    } else if (dataType === "FILE") {
        // headers.append('Content-Type', 'multpart/form-data');
        // headers.append('Accept', 'multpart/form-data');
    };

    headers.append('Authorization', `Bearer ${sessionStorage.getItem('access_token')}`);

    // || __________________  ЗАДАЕМ URL ЗАПРОСА  _______________________ ||
    let url = `${import.meta.env.VITE_API_URL}${endpoint}`;

    // || __________________  ЗАДАЕМ PAYLOAD ЗАПРОСА  _______________________ ||
    let payload = null;
    if (data === null) {
        payload = {
            method: method,
            headers: headers
        };
    } else {
        if (dataType === "JSON") {
            payload = {
                method: method,
                headers: headers,
                body: JSON.stringify(data)
            };
        } else if (dataType === "FILE") {
            payload = {
                method: method,
                headers: headers,
                body: data
            };
        } else {
            payload = {
                method: method,
                headers: headers
            };
        };
    };

    // || __________________  ОТПРАВЛЯЕМ ЗАПРОС  _______________________ || 
    let response = await fetch(url, payload);
    // || __________________  ПОЛУЧАЕМ ОТВЕТ  _______________________ || 
    let result = await response.json();

    return result;

}