class csv_obj_stack:
	def __init__(self):
		self.stack = []
	def push(self, obj):
		self.stack.append(obj)

	def top(self):
		if len(self.stack) == 0:
			return None

		last = len(self.stack) - 1
		return self.stack[last]

	def pop(self):
		if len(self.stack) == 0:
			return

		last = len(self.stack) - 1
		self.stack.pop(last)

	def pop_sub_stack(self, dr_rec_type):
		if len(self.stack) == 0:
			return

		last = len(self.stack) - 1
		last_pop = False

		for i in range(last, -1, -1):
			if last_pop:
				continue
			if self.top().get_rec_type == dr_rec_type:
				last_pop = True
			self.pop()