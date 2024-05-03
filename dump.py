from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.label import Label
from kivy.clock import Clock
import subprocess

class KddFeatureExtractorGUI(App):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.data_queue = []
        self.kdd_feature_extractor = subprocess.Popen(['./kdd99extractor', '-e'], stdout=subprocess.PIPE, universal_newlines=True)

    def build(self):
        self.layout = BoxLayout(orientation='vertical')
        self.data_display = BoxLayout(orientation='vertical', spacing=5)
        self.layout.add_widget(self.data_display)
        Clock.schedule_interval(self.update_data, 0.1)  # Update every 0.1 seconds
        return self.layout

    def update_data(self, dt):
        output = self.kdd_feature_extractor.stdout.readline().strip()
        if output:
            data = output.split(',')[-4:]
            self.data_queue.append(data)
            self.update_display()

    def update_display(self):
        self.data_display.clear_widgets()
        for data in self.data_queue:
            row = BoxLayout(orientation='horizontal', spacing=10)
            for value in data:
                label = Label(text=value)
                row.add_widget(label)
            self.data_display.add_widget(row)
        self.layout.scroll_y = 0  # Scroll to the bottom

if __name__ == "__main__":
    KddFeatureExtractorGUI().run()