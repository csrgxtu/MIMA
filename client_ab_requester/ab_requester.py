import asyncio
import time
from typing import Union

import aiohttp
import typer

app = typer.Typer()


class HttpProxy(object):
    @classmethod
    async def GetJson(
        cls, url: str, headers: dict, client_session: object, timeout: int = 5
    ) -> Union[str, str]:
        """get request

        Args:
            url (str): url
            headers (dict): customized headers
            client_session (object): aio http client session
            timeout (int, optional): timeout. Defaults to 5.

        Returns:
            Union[str, str]: err, content
        """
        start_time = round(time.time() * 1000)

        try:
            async with client_session.get(url, headers=headers, timeout=timeout) as resp:
                content = await resp.text()
                print("GET {} with headers: {} {} {}ms {}".format(
                    url, headers, resp.status,
                    round(time.time() * 1000) - start_time,
                    content.replace(" ", "").replace("\n", " ")
                ))
        except asyncio.TimeoutError as e:
            print("GET {} with headers: {} {}ms Failed: timeout {}".format(
                url, headers,
                round(time.time() * 1000) - start_time, e
            ))
        except aiohttp.client_exceptions.ClientOSError as e:
            print("GET {} with headers: {} {}ms Failed: {}".format(
                url, headers,
                round(time.time() * 1000) - start_time, e
            ))


async def concurent_request() -> None:
    tasks = []
    url = 'http://10.64.131.60:80/resource/32'
    http_session = aiohttp.ClientSession()
    while True:
        if len(tasks) > 256:
            await asyncio.gather(*tasks)
            tasks = []

        tasks.append(HttpProxy.GetJson(
            url, {}, http_session, 1
        ))

    await http_session.close()


@app.command()
def requester() -> None:
    loop = asyncio.get_event_loop()
    loop.run_until_complete(concurent_request())


if __name__ == '__main__':
    time.sleep(15)
    app()
