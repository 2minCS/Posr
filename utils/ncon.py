from rich.console import Console
from rich._export_format import CONSOLE_HTML_FORMAT
from rich.terminal_theme import TerminalTheme

class NewConsole(Console):
    def save_text(self, path: str, *, clear: bool = True, styles: bool = False) -> None:
        """Modified save_text method to not overwrite. Generate text from console and save to a given location (requires record=True argument in constructor).

        Args:
            path (str): Path to write text files.
            clear (bool, optional): Clear record buffer after exporting. Defaults to ``True``.
            styles (bool, optional): If ``True``, ansi style codes will be included. ``False`` for plain text.
                Defaults to ``False``.

        """
        text = self.export_text(clear=clear, styles=styles)
        with open(path, "at", encoding="utf-8") as write_file:
            write_file.write(text)
    def save_html(
        self,
        path: str,
        *,
        theme: TerminalTheme = None,
        clear: bool = True,
        code_format: str = CONSOLE_HTML_FORMAT,
        inline_styles: bool = False,
            ) -> None:
        """Modified save_html method to not overwrite. Generate HTML from console contents and write to a file (requires record=True argument in constructor).

        Args:
            path (str): Path to write html file.
            theme (TerminalTheme, optional): TerminalTheme object containing console colors.
            clear (bool, optional): Clear record buffer after exporting. Defaults to ``True``.
            code_format (str, optional): Format string to render HTML. In addition to '{foreground}',
                '{background}', and '{code}', should contain '{stylesheet}' if inline_styles is ``False``.
            inline_styles (bool, optional): If ``True`` styles will be inlined in to spans, which makes files
                larger but easier to cut and paste markup. If ``False``, styles will be embedded in a style tag.
                Defaults to False.

        """
        html = self.export_html(
            theme=theme,
            clear=clear,
            code_format=code_format,
            inline_styles=inline_styles,
        )
        with open(path, "at", encoding="utf-8") as write_file:
            write_file.write(html)
    