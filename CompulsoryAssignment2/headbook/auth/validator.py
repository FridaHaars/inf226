from wtforms.validators import ValidationError
import colour 
from datetime import datetime 



# Helpers to validate profile form input

''' Validate age, range: 12-117.
The minimum requirement was chosen based on the fact that I thought 12 seemed sound.
The maximum requirement was at first 100, but then I googled the oldest person in the
world throughout history, and found that he (Jiroemon Kimura, 1897-2013) (RIP) turned 
116 years and 54 days. I'd feel real bad if someone his age were to sign up and were
disallowed (however unlikely).
'''
def check_age(form, date):
    if date.data:
        today = datetime.today()
        age = today.year - date.data.year - ((today.month, today.day) < (date.data.month, date.data.day))
        if age < 12 or age > 117:
            raise ValidationError('Age must be between 12 and 117.')
        

''' Validate color
Source: User niraj's response to this Q: https://stackoverflow.com/questions/42876366/
Requirements: colour library (pip install colour)'''
def check_color(form, color):
    if color.data:
        try:
            color_value = color.data.replace(' ', '')
            colour.Color(color_value)
        except ValueError: 
            raise ValidationError('Please choose a valid color.')


''' Validate about, character range: 3-300 '''
def check_about(form, input):
    if input.data:
        if len(input.data) not in range(3, 301): 
            raise ValidationError('About section must be between 3 and 300 characters.')