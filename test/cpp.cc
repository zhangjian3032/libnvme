#include <iostream>
#include <libnvme.h>

int main()
{
	nvme_root_t r;
	nvme_subsystem_t s;
	nvme_ctrl_t c;
	nvme_path_t p;
	nvme_ns_t n;

	r = nvme_scan();
	if (!r)
		return -1;

	nvme_for_each_subsystem(r, s) {
		std::cout <<  nvme_subsystem_get_name(s) << " - NQN=" << nvme_subsystem_get_nqn(s) << "\n";
		nvme_subsystem_for_each_ctrl(s, c) {
			std::cout << " `- " << nvme_ctrl_get_name(c) << " " <<
				nvme_ctrl_get_transport(c) << " " <<
				nvme_ctrl_get_address(c) << " " <<
				nvme_ctrl_get_state(c) << "\n";
			nvme_ctrl_for_each_ns(c, n)
				std::cout << "   `- " << nvme_ns_get_name(n) <<
					"lba size:" << nvme_ns_get_lba_size(n) << " lba max:" <<
					nvme_ns_get_lba_count(n) << "\n";
			nvme_ctrl_for_each_path(c, p)
				std::cout << "   `- " << nvme_path_get_name(p) << " " <<
					nvme_path_get_ana_state(p) << "\n";
		}
		nvme_subsystem_for_each_ns(s, n) {
			std::cout << "   `- " << nvme_ns_get_name(n) <<
				"lba size:" << nvme_ns_get_lba_size(n) << " lba max:" <<
					nvme_ns_get_lba_count(n) << "\n";
		}
	}
	std::cout << "\n";

	return 0;
}
