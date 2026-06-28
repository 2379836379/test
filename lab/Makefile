CC      = gcc
CFLAGS  = -Wall -Wextra -O2
LDFLAGS = -lpcap -lpthread
TARGET  = inc
SRCS    = main.c lab.c
OBJS    = $(SRCS:.c=.o)
CFG     = ranks.cfg
HOSTS   = host1 host2 host3 host4
N       = 4

.PHONY: all clean setup_env setup_topo clean_topo kill test_allreduce test

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c common.h
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET) *.log *.nslog output-*.data input-*.data expected-allreduce.data

setup_env:
	apt install -y libpcap-dev
	docker image build -t node .

setup_topo:
	./setup_star.sh setup

clean_topo:
	./setup_star.sh clean

kill:
	-@for c in router $(HOSTS); do docker exec $$c pkill -f $(TARGET) 2>/dev/null; done

define run-allreduce
	@$(MAKE) -s kill; sleep 1
	rm -f output-*.data input-*.data expected-allreduce.data *.log
	bash helper.sh gen $(N) 262144
	bash helper.sh sum $(N)
	docker cp $(TARGET) router:/app/$(TARGET)
	docker exec -dit router bash -c "cd /app; ./$(TARGET) router $(CFG) allreduce > router.log 2>&1"
	@sleep 1
	@for c in $(HOSTS); do \
		docker exec -dit $$c bash -c "cd /app; ./$(TARGET) $$c $(CFG) allreduce > $$c.log 2>&1"; \
	done
	@echo "running 'allreduce', waiting for hosts to finish ..."
	@for i in $$(seq 1 90); do \
		done=1; \
		for c in $(HOSTS); do docker exec $$c pgrep -f $(TARGET) >/dev/null 2>&1 && done=0; done; \
		[ $$done -eq 1 ] && break; sleep 1; \
	done
	@$(MAKE) -s kill
	@echo "==================== check (allreduce) ===================="
	@bash helper.sh check allreduce $(N)
endef

test_allreduce: $(TARGET) ; $(run-allreduce)
test: test_allreduce
